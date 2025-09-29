#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <elf.h>
#include "spoof.h"


static inline void refresh_views(char **p_data, Elf64_Ehdr **ehdr, Elf64_Phdr **phdr_base) 
{
    *ehdr = (Elf64_Ehdr*)(*p_data); // get pointer elf header, given all of the changes made to file data
    *phdr_base = (Elf64_Phdr*)(*p_data + (*ehdr)->e_phoff);  //  get pointer to program header base
}


static bool append_null_section(char **p_data, size_t *p_len) 
{
    Elf64_Shdr sh = { 0 }; // prepare a zeroed section header struct
    char *buf = NULL; 

    if (!(buf = realloc(*p_data, *p_len + sizeof sh))) // resizes the existing blob to make room for one more section header at the end
        return false;

    *p_data = buf; // propagate the (possibly moved) pointer back to the caller
    memcpy(*p_data + *p_len, &sh, sizeof sh); // write the new zeroed header at the end of the buffer
    *p_len += sizeof sh; // update the caller’s recorded buffer size.
    
    return true;
}

static bool append_named_section(char **p_data, size_t *p_len, const Elf64_Shdr *hdr) 
{
    char *buf = NULL;

    if (!(buf = realloc(*p_data, *p_len + sizeof *hdr))) 
        return false;

    *p_data = buf; // caller pointer set to resized blob
    memcpy(*p_data + *p_len, hdr, sizeof *hdr); // write the new section header at the end of the buffer
    *p_len += sizeof *hdr; // update buffer size

    return true;
}

static bool build_section_headers(char *shstrtab, size_t shstr_cap, size_t *shstr_len, size_t *off_init,
                                  size_t *off_data, size_t *off_fini, size_t *off_text, size_t *off_shstr) 
 {

    const char *names[] = {".init", ".data", ".fini", ".text", ".shstrtab"}; // make array of section names
    const int names_count = (int)(sizeof(names) / sizeof(names[0]));
    size_t *offs[] = {off_init, off_data, off_fini, off_text, off_shstr}; // make array of section header offsets


    *shstr_len = 1; // .shstrtab must start with a leading NUL byte

    for (size_t i = 0; i < (size_t)names_count; ++i) {

        size_t name_bytes = strlen(names[i]) + 1; // include NUL terminator
    
        if (*shstr_len + name_bytes > shstr_cap) // avoid overflow 
            return false; 

        *offs[i] = *shstr_len; // sh_name offset
        memcpy(shstrtab + *shstr_len, names[i], name_bytes); // copy name+NUL
        *shstr_len += name_bytes;  // advance
    }
    
    return true;
}

/* --- split the RX PT_LOAD: [ .init | .data | .fini ] --- */
static bool add_data_section(char **p_data, size_t *p_len, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr_base,
                             size_t init_off, size_t data_off, size_t fini_off, size_t *sec_count)
{
    /* --- find RX segment --- */
    const Elf64_Phdr *rx = NULL;
    
    for (int i = 0; i < ehdr->e_phnum; ++i) {

        const Elf64_Phdr *p = (const Elf64_Phdr*)((uint8_t*)phdr_base + (size_t)i * ehdr->e_phentsize);

        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) { 
            rx = p; 
            break;
         }        
    }

    if (rx == NULL) 
        return false;
    
    const Elf64_Addr seg_va   = rx->p_vaddr;
    const Elf64_Off  seg_off  = rx->p_offset;
    const Elf64_Xword seg_sz  = rx->p_filesz;

    /* --- determine split points --- */
    Elf64_Addr entry = ehdr->e_entry;
    Elf64_Xword init_sz;

    if (entry < seg_va) {
        init_sz = 0; 
    } else if (entry >= seg_va + seg_sz) {
        init_sz = seg_sz;
    } else {
        init_sz = (Elf64_Xword)(entry - seg_va + 1); // init includes entry 
    }

    /* --- split remaining bytes safely: [init][gap][data][fini] --- */
    Elf64_Xword gap_after_entry = 1; // bytes to skip after entry 
    Elf64_Xword bytes_after_init = (seg_sz > init_sz) ? (seg_sz - init_sz) : 0;
    Elf64_Xword bytes_after_gap = (bytes_after_init > gap_after_entry) ? (bytes_after_init - gap_after_entry) : 0;
    Elf64_Xword fini_sz = (bytes_after_gap >= 8) ? 8 : bytes_after_gap;
    Elf64_Xword data_sz = (bytes_after_gap > fini_sz) ? (bytes_after_gap - fini_sz) : 0;

    const Elf64_Addr data_start_va = seg_va + init_sz + ((bytes_after_init >= gap_after_entry) ? gap_after_entry : bytes_after_init);
    const Elf64_Off data_start_off = seg_off + init_sz + ((bytes_after_init >= gap_after_entry) ? gap_after_entry : bytes_after_init);

    Elf64_Shdr init_hdr = {
        .sh_name = (Elf64_Word)init_off,
        .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
        .sh_addr = seg_va,
        .sh_offset = seg_off,
        .sh_size = init_sz,
        .sh_addralign = SECTION_ALIGN,
        };
        
        
        Elf64_Shdr data_hdr = {
        .sh_name = (Elf64_Word)data_off,
        .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_WRITE, // spoofed as data 
        .sh_addr = data_start_va,
        .sh_offset = data_start_off,
        .sh_size = data_sz,
        .sh_addralign = SECTION_ALIGN,
        };
        
        
        Elf64_Shdr fini_hdr = {
        .sh_name = (Elf64_Word)fini_off,
        .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
        .sh_addr = seg_va + init_sz + ((bytes_after_init >= gap_after_entry) ? gap_after_entry : bytes_after_init) + data_sz,
        .sh_offset = seg_off + init_sz + ((bytes_after_init >= gap_after_entry) ? gap_after_entry : bytes_after_init) + data_sz,
        .sh_size = fini_sz,
        .sh_addralign = SECTION_ALIGN,
        };
        
        
        if (!append_named_section(p_data, p_len, &init_hdr))
            return false;
        ++*sec_count;
          
        if (!append_named_section(p_data, p_len, &data_hdr))
            return false;
        ++*sec_count;
        
        if (!append_named_section(p_data, p_len, &fini_hdr))
            return false;
        ++*sec_count;
        
        return true; 
}

/* --- create a spoofed .text for the RW PT_LOAD --- */
static bool add_text_section(char **p_data, size_t *p_len,
                            Elf64_Ehdr *ehdr, Elf64_Phdr *phdr_base,
                            size_t text_name_offset, size_t *sec_count) 
{
    const Elf64_Phdr *rw = NULL, *rx = NULL, *any = NULL, *src = NULL;
    
    for (int i = 0; i < ehdr->e_phnum; ++i) {

        const Elf64_Phdr *p = (const Elf64_Phdr*)((uint8_t*)phdr_base + (size_t)i * ehdr->e_phentsize);

        if (p->p_type != PT_LOAD)
            continue;

        any = any ? any : p;

        if (p->p_flags & PF_X) { 
            if (rx == NULL) 
                rx = p; 
            else 
                rw = p; 
        }
    }
    
    /* --- prefer RW, else RX/RWX, else any LOAD --- */
    src = rw ? rw : (rx ? rx : any);

    if (src == NULL) return false;

    Elf64_Shdr text_hdr = {
    .sh_name      = (Elf64_Word)text_name_offset,
    .sh_type      = SHT_PROGBITS,
    .sh_flags     = SHF_ALLOC | SHF_EXECINSTR,  // spoof as text either way
    .sh_addr      = src->p_vaddr,
    .sh_offset    = src->p_offset,
    .sh_size      = src->p_filesz,
    .sh_addralign = SECTION_ALIGN,
    };

    if (!append_named_section(p_data, p_len, &text_hdr)) 
        return false;

    ++*sec_count;

    return true;
}


static bool add_shstrtab_section(char **p_data, size_t *p_len,
                                 const char *shstrtab, size_t shstr_len,
                                 size_t shstr_name_off,
                                 size_t *shstr_index,
                                 size_t *sec_count) 
{         
    /* --- place shstrtab immediately after the final SHDR entry --- */
    Elf64_Shdr sh = {
        .sh_name      = (Elf64_Word)shstr_name_off,
        .sh_type      = SHT_STRTAB,
        .sh_offset    = *p_len + sizeof(Elf64_Shdr),
        .sh_size      = shstr_len,
        .sh_addralign = 1,
    };

    char *buf = NULL;

    if (!(buf = realloc(*p_data, *p_len + sizeof sh + shstr_len))) 
        return false;

    *p_data = buf;
    memcpy(*p_data + *p_len, &sh, sizeof sh);
    *shstr_index = *sec_count;
    *p_len += sizeof sh;

    memcpy(*p_data + *p_len, shstrtab, shstr_len);
    *p_len += shstr_len;

    ++*sec_count;

    return true;
}

bool spoof_sections_table(char **p_data, size_t *p_data_len)
{
    if (!p_data || !*p_data || !p_data_len)
        return false;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)(*p_data);
    Elf64_Phdr *phdr_base = NULL;
    size_t original_size = *p_data_len;
    size_t sec_count = 0;
    size_t shstr_index = 0;

    char shstr[128] = {0};
    size_t shstr_len = 0;
    size_t off_init = 0, off_data = 0, off_fini = 0, off_text = 0, off_shstr = 0;

    if (!build_section_headers(shstr, sizeof shstr, &shstr_len,
                               &off_init, &off_data, &off_fini, &off_text, &off_shstr))
        return false;

    /* --- section header table start = current EoF --- */
    if (!append_null_section(p_data, p_data_len)) 
        return false;

    ++sec_count;
    
    /* ---- after possible realloc, refresh views before reading PHDRs --- */
    refresh_views(p_data, &ehdr, &phdr_base);

    if (!add_data_section(p_data, p_data_len, ehdr, phdr_base,
                          off_init, off_data, off_fini, &sec_count))
        return false;

    /* --- previous call may reallocate, refresh again --- */
    refresh_views(p_data, &ehdr, &phdr_base);

    if (!add_text_section(p_data, p_data_len, ehdr, phdr_base, off_text, &sec_count))
        return false;

    if (!add_shstrtab_section(p_data, p_data_len, shstr, shstr_len,
                              off_shstr, &shstr_index, &sec_count))
        return false;

    /* --- finalize ELF header fields --- */
    refresh_views(p_data, &ehdr, &phdr_base);
    ehdr->e_shoff     = (Elf64_Off)original_size;
    ehdr->e_shentsize = (Elf64_Half)sizeof(Elf64_Shdr);
    ehdr->e_shnum     = (Elf64_Half)sec_count;
    ehdr->e_shstrndx  = (Elf64_Half)shstr_index;

    printf("[+] section header table spoofed\n");

    return true;
}