
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tracers.h"

static inline uint64_t u64_max(uint64_t a, uint64_t b) 
{ 
    return a > b ? a : b; 
}

// ===== offsets inside the stub for immediate patching; keep in sync with stub bytes below =====
enum { 
    DD_OFF_DELTA = 11,
    DD_OFF_ANCHOR_IMM64 = 13,  
    DD_OFF_ACTENTRY_IMM64 = 53 
};

bool disable_tracers(uint8_t **p_data, size_t *p_size) 
{
    uint8_t *data = NULL;
    size_t size = 0;
    bool result = false;

    Elf64_Ehdr *ehdr = NULL;
    Elf64_Phdr *phdr_base = NULL;
    Elf64_Phdr *text = NULL;
    int text_seg_idx = -1;

    uint64_t ph_bytes = 0;
    uint64_t enc_start_off = 0; 
    uint64_t text_file_end = 0;
    uint64_t stub_file_off = 0;

    uint64_t actual_entry = 0;
    uint64_t stub_va = 0;
    uint64_t anchor_va = 0; 

    uint8_t *resized_data = NULL;
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

    // ===== Find first PF_X PT_LOAD =====
    for (int idx = 0; idx < ehdr->e_phnum; ++idx) {

        Elf64_Phdr *p = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)idx * ehdr->e_phentsize);

        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) { 
            text = p; 
            text_seg_idx = idx; 
            break; 
        }
    }

    if (text == NULL) { 
        fprintf(stderr, "[!] could not find PF_X segment\n"); 
        goto exit;
    }

    // ===== calculate stub placement =====
    enc_start_off = u64_max((uint64_t)ehdr->e_phoff + ph_bytes, (uint64_t)text->p_offset);
    text_file_end = text->p_offset + text->p_filesz; // before extension

    if (enc_start_off < text->p_offset || enc_start_off > text_file_end) {
        fprintf(stderr, "[!] bogus range inside PF_X\n");
        goto exit;
    }

    stub_file_off = text_file_end;
    stub_va       = text->p_vaddr + text->p_filesz;
    actual_entry  = ehdr->e_entry;

      // ===== anti-debugging stub =====
      unsigned char stub[] = {
        /*00*/ 0x57,                               // push rdi
        /*01*/ 0x56,                               // push rsi                    
        /*02*/ 0x52,                               // push rdx                   
        /*03*/ 0x53,                               // push rbx                   
        /*04*/ 0x48, 0x8D, 0x1D,                   // [lea rip+0]
        /*07*/ 0x00, 0x00, 0x00, 0x00,             // disp32 = 0
        /*11*/ 0x48, 0xB8,                         // mov rax, imm64
        /*13*/ 0,0,0,0,0,0,0,0,                    // imm64 (anchor_va)         
        /*21*/ 0x48, 0x29, 0xC3,                   // sub rbx, rax   ; compute the slide
        /*24*/ 0x48, 0x31, 0xC0,                   // xor rax, rax 
        /*27*/ 0x31, 0xFF,                     	   // xor edi,edi
        /*29*/ 0x31, 0xF6,                	       // xor esi,esi
        /*31*/ 0x31, 0xD2,                	       // xor edx,edx
        /*33*/ 0x45, 0x31, 0xD2,             	   // xor r10d,r10d
        /*36*/ 0xB0, 0x65,                	       // mov al,0x65    ; ptrace (101)
        /*38*/ 0x0F, 0x05,                	       // syscall
        /*40*/ 0x74, 0x09,                	       // je +0x0B       ; if rax==0 skip exit 
        /*42*/ 0x40, 0xb7, 0x01,             	   // mov dil,0x1    ; EXIT_FAILURE
        /*45*/ 0x31, 0xC0,                	       // xor eax,eax
        /*47*/ 0xB0, 0x3C,                         // mov al,0x3c    ; exit (60)
        /*49*/ 0x0F, 0x05,                         // syscall
        /*51*/ 0x48,0xB8,                          // mov rax, imm64 
        /*53*/ 0,0,0,0,0,0,0,0,                    // imm64 (actual_entry)
        /*61*/ 0x48,0x01,0xD8,                     // add rax, rbx   ; rax==OEP+slide
        /*64*/ 0x5B,                               // pop rbx
        /*65*/ 0x5A,                               // pop rdx 
        /*66*/ 0x5E,                               // pop rsi 
        /*67*/ 0x5F,                               // pop rdi
        /*68*/ 0xFF, 0xE0                          // jmp rax  
       };
       

    // ===== patch immediates =====
    anchor_va = stub_va + DD_OFF_DELTA;
    memcpy(stub + DD_OFF_ANCHOR_IMM64, &anchor_va, sizeof(uint64_t));
    memcpy(stub + DD_OFF_ACTENTRY_IMM64, &actual_entry, sizeof(uint64_t));

    // ===== calculate size_needed, reallocate pointer, zero the memory (before writing) =====
    size_needed = stub_file_off + sizeof(stub);

    if (size_needed > size) 
    {     
        if ( ! (resized_data = (uint8_t *)realloc(data, (size_t)size_needed)) ) 
        { 
            fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
            return false; 
        }

        memset(resized_data + size, 0x00, (size_t)(size_needed - size));

        data = resized_data; 
        size = (size_t)size_needed; 

        *p_data = data; 
        *p_size = size;

        // refresh views
        ehdr = (Elf64_Ehdr *)data;
        phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
        text = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)text_seg_idx * ehdr->e_phentsize);
    }

    // ===== write the stub =====
    memcpy(data + stub_file_off, stub, sizeof(stub));

    // ===== extend segment so loader maps the stub =====
    text->p_filesz += sizeof(stub);
    text->p_memsz  += sizeof(stub);

    // Switch entry to stub
    ehdr->e_entry = stub_va;

    printf("[+] anti-trace stub inserted (PTRACE_TRACEME)\n");
    result = true;
    
exit:
    return result;
}