#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "strip.h"

static Elf64_Shdr *extract_section_table(char* data, int* p_sec_count, int* p_str_index) 
{  
    if (!data || !p_sec_count || !p_str_index) 
        return NULL;
    
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)data;
    Elf64_Off section_offset = ehdr->e_shoff;
    
    *p_sec_count = ehdr->e_shnum;
    *p_str_index = ehdr->e_shstrndx;

    ehdr->e_shoff = 0;
    ehdr->e_shnum = 0;
    ehdr->e_shstrndx = 0;

    return (Elf64_Shdr*)(data + section_offset);
}

static bool wipe_section_headers(char* data, Elf64_Shdr* sections, int sec_count, int str_index)
{
    for (int i = 0; i < sec_count; i++) {

        if (sections[i].sh_link == (Elf64_Word)str_index) {
            fprintf(stderr, "[!] section %d is still linked to string index\n", i);
            return false;
        }

        if (i == str_index) {
            memset(data + sections[i].sh_offset, 0, sections[i].sh_size);
        }
    }

    memset(sections, 0, sec_count * sizeof(Elf64_Shdr));
    return true;
}

bool strip_sections_table(char* data)
{
    int section_count = 0;
    int str_index = 0;
    Elf64_Shdr* sections = NULL;
    bool result = false;
    
    if (!(sections = extract_section_table(data, &section_count, &str_index))) {
        fprintf(stderr, "[!] section header table not found\n");
        goto exit;
    }

    if (!wipe_section_headers(data, sections, section_count, str_index))
        goto exit;
    

    printf("[+] section header table removed\n");
    result = true;

exit:
    return result;
}



