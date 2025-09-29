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


/* --- build a simple derangement --- */
static void build_rotation_perm(size_t element_count, size_t *permutation) 
{
    if (element_count < 2)
        return;
 
    size_t rotation_step = (element_count == 2) ? 1u : (size_t)(rand() % (element_count - 1)) + 1u; // avoids fixed points 

    for (size_t i = 0; i < element_count; ++i) {
        permutation[i] = (i + rotation_step) % element_count;
    }
}

bool shuffle_dynsym_names(char **p_data, size_t *p_size) 
{
    if (!p_data || !*p_data || !p_size)
        return false;

    uint8_t *base = NULL;
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Shdr *shdr_base = NULL;
    Elf64_Shdr *dynsym_sh = NULL;
    Elf64_Shdr *dynstr_sh = NULL;
    Elf64_Half dynsym_idx = 0;
    Elf64_Half dynstr_idx = 0;

    Elf64_Sym *symtab = NULL;
    size_t sym_count = 0;

    Elf64_Sym *eligible_syms[MAX_SYMBOLS];
    Elf64_Word name_offsets[MAX_SYMBOLS];
    size_t permutation[MAX_SYMBOLS];
    size_t eligible_count = 0;

    size_t old_off = 0, old_sz = 0, new_off = 0, new_sz = 0;
    char *grown = NULL;
    bool result = false;

    base = (uint8_t *)*p_data;
    if (*p_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "[!] too small for ELF header\n");
        goto exit;
    }

    ehdr = (Elf64_Ehdr *)base;
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0) {
        fprintf(stderr, "[!] missing/invalid section header table\n");
        goto exit;
    }

    shdr_base = (Elf64_Shdr *)(base + ehdr->e_shoff);

    dynsym_sh = NULL; 
    dynstr_sh = NULL; 
    dynsym_idx = dynstr_idx = 0;

    for (size_t i = 0; i < ehdr->e_shnum; ++i) {

        if (shdr_base[i].sh_type == SHT_DYNSYM) {
            dynsym_sh = &shdr_base[i]; 
            dynsym_idx = (Elf64_Half)i;

            if (shdr_base[i].sh_link < ehdr->e_shnum) {
                dynstr_sh = &shdr_base[shdr_base[i].sh_link];
                dynstr_idx = (Elf64_Half)shdr_base[i].sh_link;
            }

            break;
        }
    }

    if (dynsym_sh == NULL) { 
        fprintf(stderr, "[!] dynsym section does not exist\n"); 
        goto exit; 
    }

    if (!dynstr_sh || dynstr_sh->sh_type != SHT_STRTAB) {
        fprintf(stderr, "[!] dynsym has no valid linked dynstr\n");
        goto exit;
    }

    if (dynsym_sh->sh_offset + dynsym_sh->sh_size > *p_size ||
        dynstr_sh->sh_offset + dynstr_sh->sh_size > *p_size) {
        fprintf(stderr, "[!] section out of file bounds\n");
        goto exit;
    }

    /* --- duplicate dynsym at EOF and repoint the section header --- */
    old_off = (size_t)dynsym_sh->sh_offset;
    old_sz  = (size_t)dynsym_sh->sh_size;
    new_off = *p_size;
    new_sz  = *p_size + old_sz;

    if (!(grown = (char *)realloc(*p_data, new_sz))) { 
        fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
        goto exit; 
    }

    memcpy(grown + new_off, (char *)*p_data + old_off, old_sz);

    *p_data = grown; 
    *p_size = new_sz; 
    base = (uint8_t *)grown;

    /* --- refresh views after realloc --- */
    ehdr = (Elf64_Ehdr *)base;
    shdr_base = (Elf64_Shdr *)(base + ehdr->e_shoff);
    dynsym_sh = &shdr_base[dynsym_idx];
    dynstr_sh = &shdr_base[dynstr_idx];

    dynsym_sh->sh_offset = (Elf64_Off)new_off;

    /* --- build pool bounded by dynsym size --- */
    symtab = (Elf64_Sym *)(base + dynsym_sh->sh_offset);
    sym_count = (size_t)(dynsym_sh->sh_size / sizeof(Elf64_Sym));

    eligible_count = 0;

    for (size_t i = 1; i < sym_count; ++i) { // skip NULL symbol 
        
        Elf64_Sym *s = &symtab[i];
        unsigned bind = ELF64_ST_BIND(s->st_info);
        unsigned type = ELF64_ST_TYPE(s->st_info);
        bool ok_bind = (bind == STB_GLOBAL) || (bind == STB_WEAK);
        bool ok_type = (type == STT_FUNC) || (type == STT_OBJECT) || (type == STT_NOTYPE);
        bool is_export = (s->st_value != 0);

        if (!ok_bind || !ok_type)
            continue;

        if (!SHUFFLE_IMPORTS && !is_export) // exports-only when disabled 
            continue; 

        if (s->st_name >= dynstr_sh->sh_size) // name must be inside dynstr 
            continue; 

        if (eligible_count < MAX_SYMBOLS) {
            eligible_syms[eligible_count] = s;
            name_offsets[eligible_count]  = s->st_name;
            ++eligible_count;
        }

    }

    if (eligible_count < 2) {
        printf("[!] dynsym shuffle skipped (eligible=%zu)\n", eligible_count);
        goto exit;
    }

    srand((unsigned)time(NULL)); // seed rng
    build_rotation_perm(eligible_count, permutation);

    for (size_t i = 0; i < eligible_count; ++i) {
        eligible_syms[i]->st_name = name_offsets[permutation[i]];
    }

    printf("[+] dynamic symbol names shuffled (changed=%zu) [%s]\n",
           eligible_count, SHUFFLE_IMPORTS ? "imports+exports" : "exports-only");

    result = true;

exit:
    return result;
}
