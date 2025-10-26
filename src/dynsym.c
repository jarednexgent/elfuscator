
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dynsym.h"

static size_t random_step_no_fixed_point(size_t element_count)
{
    size_t rotation_step = 0;
    size_t range = 0;

    if (element_count == DERANGEMENT_PAIR_SIZE) {
        rotation_step = ROTATION_MIN_STEP;
        return rotation_step;
    }

    range = element_count - ROTATION_MIN_STEP;
    rotation_step = (size_t)(rand() % range) + ROTATION_MIN_STEP;
    return rotation_step;
}

static void build_rotation_perm(size_t element_count, size_t *permutation) 
{
    size_t rotation_step = 0;

    if (element_count < DERANGEMENT_MIN_ELEMENTS) {
        return;
    }

    rotation_step = random_step_no_fixed_point(element_count);

    for (size_t index = 0; index < element_count; ++index) {
        permutation[index] = (index + rotation_step) % element_count;
    }
}

static bool refresh_core_views(uint8_t *base,
                               Elf64_Ehdr **out_ehdr,
                               Elf64_Shdr **out_shdr_base)
{
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Shdr *shdr_base = NULL;

    if (base == NULL) {
        return false;
    }

    ehdr = (Elf64_Ehdr *)base;

    if (ehdr->e_shoff == 0) {
        return false;
    }

    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        return false;
    }

    if (ehdr->e_shnum == 0) {
        return false;
    }

    shdr_base = (Elf64_Shdr *)(base + ehdr->e_shoff);

    *out_ehdr = ehdr;
    *out_shdr_base = shdr_base;
    return true;
}

static bool find_dynsym_and_dynstr(Elf64_Ehdr *ehdr,
                                   Elf64_Shdr *shdr_base,
                                   Elf64_Shdr **out_dynsym,
                                   Elf64_Half *out_dynsym_idx,
                                   Elf64_Shdr **out_dynstr,
                                   Elf64_Half *out_dynstr_idx)
{
 
    Elf64_Shdr *dynsym_sh = NULL;
    Elf64_Shdr *dynstr_sh = NULL;
    Elf64_Half dynsym_idx = 0;
    Elf64_Half dynstr_idx = 0;

    if (ehdr == NULL || shdr_base == NULL) {
        return false;
    }

    for (size_t idx = 0; idx < ehdr->e_shnum; ++idx) {
        if (shdr_base[idx].sh_type == SHT_DYNSYM) {
            dynsym_sh = &shdr_base[idx];
            dynsym_idx = (Elf64_Half)idx;

            if (shdr_base[idx].sh_link < ehdr->e_shnum) {
                dynstr_sh = &shdr_base[shdr_base[idx].sh_link];
                dynstr_idx = (Elf64_Half)shdr_base[idx].sh_link;
            }

            break;
        }
    }

    if (dynsym_sh == NULL) {
        return false;
    }

    if (dynstr_sh == NULL) {
        return false;
    }

    if (dynstr_sh->sh_type != SHT_STRTAB) {
        return false;
    }

    *out_dynsym = dynsym_sh;
    *out_dynsym_idx = dynsym_idx;
    *out_dynstr = dynstr_sh;
    *out_dynstr_idx = dynstr_idx;
    return true;
}

static bool validate_sections_in_bounds(size_t file_size,
                                        const Elf64_Shdr *dynsym_sh,
                                        const Elf64_Shdr *dynstr_sh)
{
    size_t dynsym_end = 0;
    size_t dynstr_end = 0;

    if (dynsym_sh == NULL || dynstr_sh == NULL) {
        return false;
    }

    dynsym_end = (size_t)dynsym_sh->sh_offset + (size_t)dynsym_sh->sh_size;
    dynstr_end = (size_t)dynstr_sh->sh_offset + (size_t)dynstr_sh->sh_size;

    if (dynsym_end > file_size) {
        return false;
    }

    if (dynstr_end > file_size) {
        return false;
    }

    return true;
}

static bool duplicate_section_to_eof(char **p_data,
                                     size_t *p_size,
                                     const Elf64_Shdr *section,
                                     size_t *out_old_off,
                                     size_t *out_old_sz,
                                     size_t *out_new_off)
{
    size_t old_off = 0;
    size_t old_sz = 0;
    size_t new_off = 0;
    size_t new_sz = 0;
    char *resized_data = NULL;

    if (p_data == NULL || *p_data == NULL || p_size == NULL || section == NULL) {
        return false;
    }

    old_off = (size_t)section->sh_offset;
    old_sz = (size_t)section->sh_size;
    new_off = *p_size;
    new_sz = *p_size + old_sz;

    if (!(resized_data = (char *)realloc(*p_data, new_sz))) {
        fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno));
        return false;
    }

    memcpy(resized_data + new_off, (char *)*p_data + old_off, old_sz);

    *p_data = resized_data;
    *p_size = new_sz;

    *out_old_off = old_off;
    *out_old_sz = old_sz;
    *out_new_off = new_off;
    return true;
}

static bool collect_eligible_dynamic_symbols(uint8_t *base,
                                             const Elf64_Shdr *dynsym_sh,
                                             const Elf64_Shdr *dynstr_sh,
                                             Elf64_Sym **eligible_syms,
                                             Elf64_Word *name_offsets,
                                             size_t *out_eligible_count)
{
    Elf64_Sym *symtab = NULL;
    size_t sym_count = 0;
    size_t eligible_count = 0;

    if (base == NULL || dynsym_sh == NULL || dynstr_sh == NULL) {
        return false;
    }

    if (eligible_syms == NULL || name_offsets == NULL || out_eligible_count == NULL) {
        return false;
    }

    symtab = (Elf64_Sym *)(base + dynsym_sh->sh_offset);
    sym_count = (size_t)(dynsym_sh->sh_size / sizeof(Elf64_Sym));
    eligible_count = 0;

    // index=0 is STN_UNDEF reserved dummy entry used by the loader/relocs.
    for (size_t idx = 1; idx < sym_count; ++idx) {
        Elf64_Sym *sym = NULL;
        unsigned bind = 0;
        unsigned type = 0;
        bool ok_bind = false;
        bool ok_type = false;
        bool is_export = false;

        sym = &symtab[idx];
        bind = ELF64_ST_BIND(sym->st_info);
        type = ELF64_ST_TYPE(sym->st_info);
        ok_bind = (bind == STB_GLOBAL) || (bind == STB_WEAK);
        ok_type = (type == STT_FUNC) || (type == STT_OBJECT) || (type == STT_NOTYPE);
        is_export = (sym->st_value != 0);

        if (!ok_bind || !ok_type) {
            continue;
        }

        if (!SHUFFLE_IMPORTS && !is_export) {
            continue;
        }

        if (sym->st_name >= dynstr_sh->sh_size) {
            continue;
        }

        if (eligible_count < MAX_SYMBOLS) {
            eligible_syms[eligible_count] = sym;
            name_offsets[eligible_count] = sym->st_name;
            ++eligible_count;
        }
    }

    *out_eligible_count = eligible_count;
    return true;
}

static void apply_dynsym_name_permutation(Elf64_Sym **eligible_syms,
                                          Elf64_Word *name_offsets,
                                          size_t eligible_count)
{
    size_t permutation[MAX_SYMBOLS];

    if (eligible_count < MIN_SYMBOLS) {
        return;
    }

    build_rotation_perm(eligible_count, permutation);

    for (size_t index = 0; index < eligible_count; ++index) {
        eligible_syms[index]->st_name = name_offsets[permutation[index]];
    }
}

bool shuffle_dynsym_names(char **p_data, size_t *p_size) 
{
    uint8_t *base = NULL;
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Shdr *shdr_base = NULL;

    Elf64_Shdr *dynsym_sh = NULL;
    Elf64_Shdr *dynstr_sh = NULL;
    Elf64_Half dynsym_idx = 0;
    Elf64_Half dynstr_idx = 0;

    size_t old_off = 0;
    size_t old_sz = 0; 
    size_t new_off = 0;

    Elf64_Sym *eligible_syms[MAX_SYMBOLS];
    Elf64_Word name_offsets[MAX_SYMBOLS];
    size_t eligible_count = 0;

    bool rv = false;
    bool success = false;

    if (p_data == NULL || *p_data == NULL || p_size == NULL) {
        return false;
    }

    base = (uint8_t *)*p_data;

    if (*p_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "[!] too small for ELF header\n");
        goto exit;
    }

    if (!(rv = refresh_core_views(base, &ehdr, &shdr_base))) {
        fprintf(stderr, "[!] missing/invalid section header table\n");
        goto exit;
    }

    if (!(rv = find_dynsym_and_dynstr(ehdr, shdr_base, &dynsym_sh, &dynsym_idx, &dynstr_sh, &dynstr_idx))) {
        fprintf(stderr, "[!] dynsym/dynstr not found or invalid\n");
        goto exit;
    }

    if (!(rv = validate_sections_in_bounds(*p_size, dynsym_sh, dynstr_sh))) {
        fprintf(stderr, "[!] section out of file bounds\n");
        goto exit;
    }

    if (!(rv = duplicate_section_to_eof(p_data, p_size, dynsym_sh, &old_off, &old_sz, &new_off))) {
        goto exit;
    }

    base = (uint8_t *)*p_data;

    if (!(rv = refresh_core_views(base, &ehdr, &shdr_base))) {
        fprintf(stderr, "[!] internal error after realloc\n");
        goto exit;
    }

    dynsym_sh = &shdr_base[dynsym_idx];
    dynstr_sh = &shdr_base[dynstr_idx];

    dynsym_sh->sh_offset = (Elf64_Off)new_off;

    srand((unsigned)time(NULL));

    if (!(rv = collect_eligible_dynamic_symbols(base,
                                          dynsym_sh,
                                          dynstr_sh,
                                          eligible_syms,
                                          name_offsets,
                                          &eligible_count)))
    {
        fprintf(stderr, "[!] failed to collect dynamic symbols\n");
        goto exit;
    }

    if (eligible_count < MIN_SYMBOLS) {
        printf("[!] dynsym shuffle skipped (eligible=%zu)\n", eligible_count);
        goto exit;
    }

    apply_dynsym_name_permutation(eligible_syms, name_offsets, eligible_count);

    printf("[+] dynamic symbol names shuffled (changed=%zu)\n", eligible_count);

    success = true;

exit:
    return success;
}
