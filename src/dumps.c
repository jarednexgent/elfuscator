#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dumps.h"


/* --- offsets inside the stub for immediate patching; keep in sync with stub bytes below --- */
enum {
    DD_OFF_DELTA = 8,  // push rbx (1 byte) + lea rbx, [rip+disp32] (7 bytes) = 8 bytes from stub start to the next instruction
    DD_OFF_ANCHOR_IMM64 = 10,  // mov rax, anchor (imm64 starts here)
    DD_OFF_ACTENTRY_IMM64 = 50 // mov rax, actual_entry (imm64 starts here)
};

static inline uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }

bool disable_dumps(uint8_t **p_data, size_t *p_size) 
{
    uint8_t *data = NULL;
    size_t size = 0;
    bool result = false;

    Elf64_Ehdr *ehdr = NULL;
    Elf64_Phdr *phdr_base = NULL;
    Elf64_Phdr *text = NULL;
    int text_idx = -1;

    uint64_t ph_bytes = 0;
    uint64_t enc_start_off = 0; // we don't encrypt, but we validate range math with it
    uint64_t text_file_end = 0;
    uint64_t stub_file_off = 0;

    uint64_t actual_entry = 0;
    uint64_t stub_va = 0;
    uint64_t anchor_va = 0; // VA of next instruction after LEA+disp

    uint8_t *data_grown = NULL;
    uint64_t size_needed = 0;

    if (!p_data || !*p_data || !p_size) 
        return false;

    data = *p_data; size = *p_size;

    if (unlikely(size < sizeof(Elf64_Ehdr))) {
        fprintf(stderr, "[!] insufficient ELF size: %zu\n", size);
        goto exit;
    }

    ehdr = (Elf64_Ehdr *)data;
    ph_bytes = (uint64_t)ehdr->e_phentsize * (uint64_t)ehdr->e_phnum;

    if ((uint64_t)ehdr->e_phoff + ph_bytes > size) {
        fprintf(stderr, "[!] invalid PHDR table: out of bounds\n");
        goto exit;
    }

    phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);

    /* --- Find first PF_X PT_LOAD --- */
    for (int i = 0; i < ehdr->e_phnum; ++i) {

        Elf64_Phdr *p = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)i * ehdr->e_phentsize);

        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) { 
            text = p; 
            text_idx = i; 
            break; 
        }
    }

    if (text == NULL) { 
        fprintf(stderr, "[!] could not find PF_X segment\n"); 
        goto exit;
    }

    /* --- calculate stub placement --- */
    enc_start_off = u64_max((uint64_t)ehdr->e_phoff + ph_bytes, (uint64_t)text->p_offset);
    text_file_end = text->p_offset + text->p_filesz; // before extension

    if (enc_start_off < text->p_offset || enc_start_off > text_file_end) {
        fprintf(stderr, "[!] bogus range inside PF_X\n");
        goto exit;
    }

    stub_file_off = text_file_end;
    stub_va       = text->p_vaddr + text->p_filesz;
    actual_entry  = ehdr->e_entry;

      /* --- minimal anti-dump PIC stub --- */
    unsigned char stub[] = {
        0x53,                        //  0: push rbx
        0x48,0x8D,0x1D,              //  1: lea rbx, [rip+0]             
        0x00,0x00,0x00,0x00,         //  4: disp32=0                
        0x48,0xB8,                   //  8: mov rax, imm64               
        0,0,0,0,0,0,0,0,             // 10: imm64 (anchor_va)
        0x48,0x29,0xC3,              // 18: sub rbx, rax                
        0x48,0x31,0xC0,              // 21: xor rax, rax                
        0x48,0xC7,0xC0,0x9D,0x00,0x00,0x00, // 24: mov rax, 157 (SYS_prctl)
        0xBF,0x04,0x00,0x00,0x00,    // 31: mov edi, 4   (PR_SET_DUMPABLE)
        0x31,0xF6,                   // 36: xor esi, esi
        0x31,0xD2,                   // 38: xor edx, edx
        0x41,0x31,0xD2,              // 40: xor r10d, r10d
        0x41,0x31,0xC0,              // 43: xor r8d,  r8d
        0x0F,0x05,                   // 46: syscall
        0x48,0xB8,                   // 48: mov rax, imm64 (actual_entry)
        0,0,0,0,0,0,0,0,             // 50: imm64 actual_entry
        0x48,0x01,0xD8,              // 58: add rax, rbx
        0x5B,                         // 61: pop rbx
        0xFF,0xE0                    // 62: jmp rax
    };

  
    /* --- patch immediates --- */
    anchor_va = stub_va + DD_OFF_DELTA;
    memcpy(stub + DD_OFF_ANCHOR_IMM64, &anchor_va, sizeof(uint64_t));
    memcpy(stub + DD_OFF_ACTENTRY_IMM64, &actual_entry, sizeof(uint64_t));

    /* --- calculate size_needed, reallocate pointer, zero the memory (before writing) --- */
    size_needed = stub_file_off + sizeof(stub);
    if (size_needed > size) 
    {     
        if (!(data_grown = (uint8_t *)realloc(data, (size_t)size_needed))) 
        { 
            fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
            return false; 
        }

        memset(data_grown + size, 0x00, (size_t)(size_needed - size));

        data = data_grown; 
        size = (size_t)size_needed; 

        *p_data = data; 
        *p_size = size;

        // refresh views
        ehdr = (Elf64_Ehdr *)data;
        phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
        text = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)text_idx * ehdr->e_phentsize);
    }

    /* --- write the stub --- */
    memcpy(data + stub_file_off, stub, sizeof(stub));

    /* --- extend segment so loader maps the stub --- */
    text->p_filesz += sizeof(stub);
    text->p_memsz  += sizeof(stub);

    // Switch entry to stub
    ehdr->e_entry = stub_va;

    printf("[+] anti-dump stub inserted (PR_SET_DUMPABLE=0)\n");
    result = true;
exit:
    return result;
}

