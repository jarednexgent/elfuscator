#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "strip.h"

static Elf64_Shdr *extract_section_table(char* data, int* p_sec_count, int* p_str_index) 
{  
    if (!data || !p_sec_count || !p_str_index) 
        return NULL;
    
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)data; // define file data as elf header
    Elf64_Off section_offset = ehdr->e_shoff;  // define offset to section header table
    
    *p_sec_count = ehdr->e_shnum; // number of sections
    *p_str_index = ehdr->e_shstrndx; // index of shdr string table, which contains the names of all sections

    ehdr->e_shoff = 0; // now we set offset to shdr table as zero, since we are stripping the table
    ehdr->e_shnum = 0; // set number of sections as zero
    ehdr->e_shstrndx = 0; // and do the same for the string table index

    return (Elf64_Shdr*)(data + section_offset); // return a pointer to the section header table
}

static bool wipe_section_headers(char* data, Elf64_Shdr* sections, int sec_count, int str_index)
{
    for (int idx = 0; idx < sec_count; idx++) { // loops through each section

        if (sections[idx].sh_link == (Elf64_Word)str_index) { // if section is linked to string table then we OUTTIE
            fprintf(stderr, "[!] section %d is still linked to string index\n", idx); 
            return false;
        }

        if (idx == str_index) { // wipe the content of the shdr string table
            memset(data + sections[idx].sh_offset, 0, sections[idx].sh_size);
        }
    }

    memset(sections, 0, sec_count * sizeof(Elf64_Shdr)); // wipe the section header table
    return true;
}

bool strip_sections_table(char* data)
{
    int section_count = 0;
    int str_index = 0;
    Elf64_Shdr* sections = NULL;
    bool result = false;
    
    // ===== file data in, section_count & str_index out, return pointer to section table =====
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



