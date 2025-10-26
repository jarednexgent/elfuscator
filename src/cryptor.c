/*
*  - Anchor = a file-time address embedded in the stub that points to a known place inside the stub (usually the RIP value produced by lea rbx, [rip+0]).
*
*  - Slide = runtime_address_of_anchor - anchor = how far the module was relocated at runtime (ASLR or loader mapping).
*
*  - The stub computes slide at runtime, then adds it to any file-time virtual addresses (virt_start, virt_end, actual_entry) 
*    to get their runtime addresses so the stub can operate on the correct memory and jump to the correct entry.
*/


#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cryptor.h"


// ===== legacy stub patch offsets (no mprotect) =====
enum {
    LEG_OFF_KEY_IMM8      = 50,
    LEG_OFF_ANCHOR_IMM64  = 12,
    LEG_OFF_VSTART_IMM64  = 25,
    LEG_OFF_VEND_IMM64    = 35,
    LEG_OFF_ACTENT_IMM64  = 65,
    LEG_ANCHOR_DELTA      = 10 
};

// ===== mprotect stub patch offsets =====
enum {
    MP_OFF_ANCHOR_IMM64   = 13,
    MP_OFF_VSTART1_IMM64  = 26,
    MP_OFF_VEND1_IMM64    = 36,
    MP_OFF_VSTART2_IMM64  = 99,
    MP_OFF_VEND2_IMM64    = 112,
    MP_OFF_KEY_IMM8       = 124,
    MP_OFF_ACTENT_IMM64   = 176,
    MP_ANCHOR_DELTA       = 11  
};

// ===== helper: returns the greater value =====
static inline uint64_t u64_max(uint64_t a, uint64_t b) 
{
     return a > b ? a : b; 
}

// ===== if the SHT overlaps insert_off, shift the tail (e_shoff..size) by delta and fix sh_offset. =====
static bool relocate_sht(uint8_t **p_data, 
                            size_t *p_size, 
                            Elf64_Ehdr **p_ehdr,
                            size_t insert_off, 
                            size_t delta)
{
    uint8_t *data = *p_data;
    size_t size = *p_size;
    Elf64_Ehdr *ehdr = *p_ehdr;

    if (ehdr->e_shoff == 0 || delta == 0) 
        return true;

    if ((size_t)ehdr->e_shoff < insert_off)
        return true; // SHT is before stub insertion point

    size_t old_shoff = (size_t)ehdr->e_shoff;
    size_t tail_len  = size - old_shoff;
    uint8_t *grown = NULL;

    if (!(grown = (uint8_t *)realloc(data, size + delta))) { 
        fprintf(stderr, "[!] realloc failed while moving SHT: %s\n", strerror(errno));
        return false;
    }

    memmove(grown + old_shoff + delta, grown + old_shoff, tail_len);
    memset(grown + old_shoff, 0x00, delta);

    *p_data = grown;
    *p_size = size + delta;
    *p_ehdr = (Elf64_Ehdr *)grown;

    Elf64_Shdr *shdr_base = (Elf64_Shdr *)(grown + (*p_ehdr)->e_shoff);
    (void)shdr_base; // why: will rebase after updating e_shoff

    (*p_ehdr)->e_shoff = (Elf64_Off)(old_shoff + delta);
    shdr_base = (Elf64_Shdr *)(grown + (*p_ehdr)->e_shoff);

    for (Elf64_Half idx = 0; idx < (*p_ehdr)->e_shnum; ++idx) {
        if (shdr_base[idx].sh_offset >= old_shoff) {
            shdr_base[idx].sh_offset += delta;
        }
    }

    return true;
}

bool encrypt_code_segment(uint8_t **p_data, size_t *p_size)
{
    if (!p_data || !*p_data || !p_size)
        return false;

    // ===== top-level locals =====
    uint8_t *data = NULL;
    size_t size = 0;
    bool result = false;

    // ===== ELF views =====
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Phdr *phdr_base = NULL;
    Elf64_Phdr *code_segment = NULL;
    int code_seg_idx = -1; 

    // ===== sizes/offsets =====
    uint64_t ph_size = 0;
    uint64_t encrypt_start_off = 0;
    uint64_t text_file_end = 0;
    uint64_t stub_file_off = 0;
    uint64_t size_needed = 0;

    // ===== VAs =====
    uint64_t virt_start_va = 0;
    uint64_t virt_end_va = 0;
    uint64_t actual_entry_va = 0;
    uint64_t stub_va = 0;
    uint64_t anchor_va = 0;

    // ===== misc =====
    unsigned char key = 0;
    uint8_t *resized_data = NULL;

    data = *p_data;
    size = *p_size;

    if (unlikely(size < sizeof(Elf64_Ehdr))) {
        fprintf(stderr, "[!] insufficient ELF file size: %zu\n", size);
        goto exit;
    }

    ehdr = (Elf64_Ehdr *)data;
    ph_size = (uint64_t)ehdr->e_phentsize * (uint64_t)ehdr->e_phnum;

    if ((uint64_t)ehdr->e_phoff + ph_size > size) {
        fprintf(stderr, "[!] invalid PHDR table: out of bounds\n");
        goto exit;
    }

    phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);

    // ===== find first PF_X PT_LOAD =====
    for (int idx = 0; idx < ehdr->e_phnum; ++idx) {

        Elf64_Phdr *ph = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)idx * ehdr->e_phentsize);

        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) { 
            code_segment = ph;
            code_seg_idx = idx;
            break;
        }
    }

    if (code_segment == NULL) { 
        fprintf(stderr, "[!] could not find PF_X segment\n"); 
        goto exit; 
    }

    // ===== determine what offset to encrypt =====
    encrypt_start_off = u64_max((uint64_t)ehdr->e_phoff + ph_size, (uint64_t)code_segment->p_offset);

    text_file_end = code_segment->p_offset + code_segment->p_filesz; 
    
    if (encrypt_start_off < code_segment->p_offset || encrypt_start_off >= text_file_end) {
        fprintf(stderr, "[!] encrypt_start outside PF_X (0x%jx not in [0x%jx..0x%jx))\n",
                (uintmax_t)encrypt_start_off, (uintmax_t)code_segment->p_offset, (uintmax_t)text_file_end);
        goto exit;
    }

    // ===== link-time VAs =====
    actual_entry_va = ehdr->e_entry;
    stub_va         = code_segment->p_vaddr + code_segment->p_filesz; // VA of stub start
    virt_start_va   = code_segment->p_vaddr + (encrypt_start_off - code_segment->p_offset);
    virt_end_va     = stub_va; // decrypt up to stub

    // ===== choose stub based on RWX =====
    const bool rwx = (code_segment->p_flags & PF_W) != 0; // PF_X implied by selection

    if (rwx == true) {
        // ===== legacy RWX stub (no mprotect) =====
        unsigned char stub[] = {
            0x56,                               //  0: push rsi
            0x52,                               //  1: push rdx
            0x53,                               //  2: push rbx
            0x48, 0x8D, 0x1D,                   //  3: lea rbx, [rip+0]
            0x00, 0x00, 0x00, 0x00,             //  6: disp32 = 0
            0x48, 0xB8,                         // 10: mov rax, imm64 (anchor_va)
            0,0,0,0,0,0,0,0,                    // 12: imm64 anchor_va
            0x48, 0x29, 0xC3,                   // 20: sub rbx, rax   (slide)
            0x48, 0xBE,                         // 23: mov rsi, imm64 (virt_start)
            0,0,0,0,0,0,0,0,                    // 25: imm64 virt_start
            0x48, 0xBA,                         // 33: mov rdx, imm64 (virt_end)
            0,0,0,0,0,0,0,0,                    // 35: imm64 virt_end
            0x48, 0x01, 0xDE,                   // 43: add rsi, rbx
            0x48, 0x01, 0xDA,                   // 46: add rdx, rbx
            0xB0, 0x00,                         // 49: mov al, <key>
            0x30, 0x06,                         // 51: xor BYTE PTR [rsi], al
            0xFE, 0xC0,                         // 53: inc al             
            0x48, 0xFF, 0xC6,                   // 55: inc rsi           
            0x48, 0x39, 0xD6,                   // 58: cmp rsi, rdx       
            0x72, 0xF4,                         // 61: jb  -0x0C      ; jump back to offset 51
            // after loop: compute runtime actual_entry and jump 
            0x48, 0xB8,                         // 63: mov rax, imm64 (actual_entry) 
            0,0,0,0,0,0,0,0,                    // 65: imm64 
            0x48, 0x01, 0xD8,                   // 73: add rax, rbx   ; rax += slide */
            0x5B,                               // 76: pop rbx 
            0x5A,                               // 77: pop rdx 
            0x5E,                               // 78: pop rsi 
            0xFF, 0xE0                          // 79: jmp rax 
        };

        // ===== prepare to place stub =====
        stub_file_off = text_file_end;
        size_needed   = stub_file_off + sizeof(stub);

        // ===== if SHT would be overlapped by the inserted stub, move it forward =====
        if (!relocate_sht(&data, &size, &ehdr, (size_t)stub_file_off, sizeof(stub))) 
            goto exit;

        if (size_needed > size) 
        {
            if (!(resized_data = (uint8_t *)realloc(data, (size_t)size_needed))) { 
                fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
                goto exit; 
            } 

            memset(resized_data + size, 0x00, (size_t)(size_needed - size));

            data = resized_data; 
            size = (size_t)size_needed; 

            *p_data = data; 
            *p_size = size;

            // ===== refresh views =====
            ehdr = (Elf64_Ehdr *)data;
            phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
            code_segment = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)code_seg_idx * ehdr->e_phentsize);       
        }

        // ===== generate key and patch immediates =====
        srand((unsigned)time(NULL));
        key = (unsigned char)(rand() & 0xFF); 

        anchor_va = stub_va + LEG_ANCHOR_DELTA;
        stub[LEG_OFF_KEY_IMM8] = key;
        memcpy(stub + LEG_OFF_ANCHOR_IMM64, &anchor_va,       sizeof(uint64_t));
        memcpy(stub + LEG_OFF_VSTART_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + LEG_OFF_VEND_IMM64,   &virt_end_va,     sizeof(uint64_t));
        memcpy(stub + LEG_OFF_ACTENT_IMM64, &actual_entry_va, sizeof(uint64_t));

        // ===== write stub =====
        memcpy(data + stub_file_off, stub, sizeof(stub));

        // ===== extend segment so loader maps the stub =====
        code_segment->p_filesz += sizeof(stub);
        code_segment->p_memsz  += sizeof(stub);

        // ===== set new entry and encrypt =====
        ehdr->e_entry = stub_va;

        for (uint64_t off = encrypt_start_off; off < stub_file_off; ++off) {
            data[off] ^= (uint8_t)key;
            (uint8_t)++key;
        }

        printf("[+] cryptor added (legacy RWX stub)\n");
        result = true;

    } else {
        // ===== PIE-safe mprotect stub =====
        unsigned char stub[] = {
            0x57,                               //  0: push rdi
            0x56,                               //  1: push rsi
            0x52,                               //  2: push rdx
            0x53,                               //  3: push rbx
            0x48, 0x8D, 0x1D,                   //  4: lea rbx, [rip+0]
            0x00, 0x00, 0x00, 0x00,             //  7: disp32 = 0
            0x48, 0xB8,                         // 11: mov rax, imm64 (anchor_va)
            0,0,0,0,0,0,0,0,                    // 13: imm64 anchor_va
            0x48, 0x29, 0xC3,                   // 21: sub rbx, rax   (slide)
            0x48, 0xBE,                         // 24: mov rsi, imm64 (virt_start)
            0,0,0,0,0,0,0,0,                    // 26: imm64 virt_start
            0x48, 0xBA,                         // 34: mov rdx, imm64 (virt_end)
            0,0,0,0,0,0,0,0,                    // 36: imm64 virt_end
            0x48, 0x01, 0xDE,                   // 44: add rsi, rbx   (start += slide)
            0x48, 0x01, 0xDA,                   // 47: add rdx, rbx   (end   += slide)
            // mprotect(start..end, RWX)
            0x48, 0x89, 0xF7,                   // 50: mov rdi, rsi   (addr)
            0x48, 0x81, 0xE7, 0x00, 0xF0, 0xFF, 0xFF, // 53: and rdi, -4096 (align down)
            0x48, 0x89, 0xD0,                   // 60: mov rax, rdx   (rax=end)
            0x48, 0xFF, 0xC8,                   // 63: dec rax        (end-1)
            0x48, 0x0D, 0xFF, 0x0F, 0x00, 0x00, // 66: or rax, 0xFFF  (ceil-1)
            0x48, 0xFF, 0xC0,                   // 72: inc rax        (ceil)
            0x48, 0x29, 0xF8,                   // 75: sub rax, rdi   (len)
            0x48, 0x89, 0xC6,                   // 78: mov rsi, rax   (len)
            0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00, // 81: mov rdx, 7 (PROT_RWX)
            0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // 88: mov rax, 10 (SYS_mprotect)
            0x0F, 0x05,                         // 95: syscall
            // reload start/end (clobbered regs) for loop
            0x48, 0xBE,                         // 97: mov rsi, imm64 (virt_start)
            0,0,0,0,0,0,0,0,                    // 99: imm64 virt_start
            0x48, 0x01, 0xDE,                   // 107: add rsi, rbx
            0x48, 0xBA,                         // 110: mov rdx, imm64 (virt_end)
            0,0,0,0,0,0,0,0,                    // 112: imm64 virt_end
            0x48, 0x01, 0xDA,                   // 120: add rdx, rbx
            // decrypt loop
            0xB0, 0x00,                         // 123: mov al, <key>
            0x30, 0x06,                         // 125: xor BYTE PTR [rsi], al
            0xFE, 0xC0,                         // 127: inc al
            0x48, 0xFF, 0xC6,                   // 129: inc rsi
            0x48, 0x39, 0xD6,                   // 132: cmp rsi, rdx
            0x72, 0xF4,                         // 135: jb  -0x0C
            // mprotect(start..end, RX)
            0x48, 0x89, 0xF0,                   // 137: mov rax, rsi  (rax=end)
            0x48, 0xFF, 0xC8,                   // 140: dec rax
            0x48, 0x0D, 0xFF, 0x0F, 0x00, 0x00, // 143: or rax, 0xFFF
            0x48, 0xFF, 0xC0,                   // 149: inc rax
            0x48, 0x29, 0xF8,                   // 152: sub rax, rdi  (len)
            0x48, 0x89, 0xC6,                   // 155: mov rsi, rax  (len)
            0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00, // 158: mov rdx, 5 (PROT_RX)
            0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // 165: mov rax, 10 (SYS_mprotect)
            0x0F, 0x05,                         // 172: syscall
            // jump to original entry
            0x48, 0xB8,                         // 174: mov rax, imm64 (actual_entry)
            0,0,0,0,0,0,0,0,                    // 176: imm64 actual_entry
            0x48, 0x01, 0xD8,                   // 184: add rax, rbx  (apply slide)
            0x5B,                               // 187: pop rbx
            0x5A,                               // 188: pop rdx
            0x5E,                               // 189: pop rsi
            0x5F,                               // 190: pop rdi
            0xFF, 0xE0                          // 191: jmp rax
        };

        // ===== prepare to place stub =====
        stub_file_off = text_file_end;
        size_needed   = stub_file_off + sizeof(stub);

        if (!relocate_sht(&data, &size, &ehdr, (size_t)stub_file_off, sizeof(stub))) 
            goto exit;

        if (size_needed > size) 
        {
            if ( ! (resized_data = (uint8_t *)realloc(data, (size_t)size_needed)) ) { 
                fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
                goto exit; 
            }
            
            memset(resized_data + size, 0x00, (size_t)(size_needed - size));

            data = resized_data; 
            size = (size_t)size_needed; 
            
            *p_data = data; 
            *p_size = size;

            // ===== refresh views =====
            ehdr = (Elf64_Ehdr *)data;
            phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
            code_segment = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)code_seg_idx * ehdr->e_phentsize);
        }

        // ===== generate XOR key =====
        srand((unsigned)time(NULL));
        key = (unsigned char)(rand() & 0xFF);

        // ===== patch immediates =====
        anchor_va = stub_va + MP_ANCHOR_DELTA;
        memcpy(stub + MP_OFF_ANCHOR_IMM64,  &anchor_va,       sizeof(uint64_t));
        memcpy(stub + MP_OFF_VSTART1_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + MP_OFF_VEND1_IMM64,   &virt_end_va,     sizeof(uint64_t));
        memcpy(stub + MP_OFF_VSTART2_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + MP_OFF_VEND2_IMM64,   &virt_end_va,     sizeof(uint64_t));
        stub[MP_OFF_KEY_IMM8] = key;
        memcpy(stub + MP_OFF_ACTENT_IMM64,  &actual_entry_va, sizeof(uint64_t));

        // ===== write stub =====
        memcpy(data + stub_file_off, stub, sizeof(stub));

        // ===== extend segment so loader maps the stub =====
        code_segment->p_filesz += sizeof(stub);
        code_segment->p_memsz  += sizeof(stub);

        // ===== set new entry and encrypt =====
        ehdr->e_entry = stub_va;
        
        for (uint64_t off = encrypt_start_off; off < stub_file_off; ++off) {
            data[off] ^= (uint8_t)key;
            (uint8_t)++key;
        }

        printf("[+] cryptor added (mprotect stub)\n");
        result = true;
    }

exit:
    *p_data = data; 
    *p_size = size;
    return result;
}
