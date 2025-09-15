#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cryptor.h"


/* --- legacy stub patch offsets (no mprotect) --- */
enum {
    LEG_OFF_KEY_IMM8      = 50,
    LEG_OFF_ANCHOR_IMM64  = 12,
    LEG_OFF_VSTART_IMM64  = 25,
    LEG_OFF_VEND_IMM64    = 35,
    LEG_OFF_ACTENT_IMM64  = 63,
    LEG_ANCHOR_DELTA      = 10  // stub_va + 10
};

/* --- mprotect stub patch offsets --- */
enum {
    MP_OFF_ANCHOR_IMM64   = 13,
    MP_OFF_VSTART1_IMM64  = 26,
    MP_OFF_VEND1_IMM64    = 36,
    MP_OFF_VSTART2_IMM64  = 99,
    MP_OFF_VEND2_IMM64    = 112,
    MP_OFF_KEY_IMM8       = 124,
    MP_OFF_ACTENT_IMM64   = 174,
    MP_ANCHOR_DELTA       = 11  // stub_va + 11
};

static inline uint64_t u64_max(uint64_t a, uint64_t b) 
{
     return a > b ? a : b; 
}

/* --- if the SHT sits at/after `insert_off`, shift the tail (e_shoff..size) by `delta` and fix sh_offset. --- */
static bool relocate_sht(uint8_t **p_data, size_t *p_size, Elf64_Ehdr **p_ehdr,
                                   size_t insert_off, size_t delta)
{
    uint8_t *data = *p_data;
    size_t size = *p_size;
    Elf64_Ehdr *ehdr = *p_ehdr;

    if (ehdr->e_shoff == 0 || delta == 0) 
        return true;

    if ((size_t)ehdr->e_shoff < insert_off)
        return true; // SHT is before insert; safe

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
    (void)shdr_base; // will rebase after updating e_shoff

    (*p_ehdr)->e_shoff = (Elf64_Off)(old_shoff + delta);
    shdr_base = (Elf64_Shdr *)(grown + (*p_ehdr)->e_shoff);

    for (Elf64_Half i = 0; i < (*p_ehdr)->e_shnum; ++i) {
        if (shdr_base[i].sh_offset >= old_shoff) {
            shdr_base[i].sh_offset += delta;
        }
    }

    return true;
}

bool encrypt_code_segment(uint8_t **p_data, size_t *p_size)
{
    if (!p_data || !*p_data || !p_size)
        return false;

    // --- top-level locals ---
    uint8_t *data = NULL;
    size_t size = 0;
    bool result = false;

    /* --- ELF views --- */
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Phdr *phdr_base = NULL;
    Elf64_Phdr *text_segment = NULL;
    int text_seg_index = -1;

    /* --- sizes/offsets --- */
    uint64_t ph_size = 0;
    uint64_t encrypt_start_off = 0;
    uint64_t text_file_end = 0;
    uint64_t stub_file_off = 0;
    uint64_t size_needed = 0;

    /* --- VAs --- */
    uint64_t virt_start_va = 0;
    uint64_t virt_end_va = 0;
    uint64_t actual_entry_va = 0;
    uint64_t stub_va = 0;
    uint64_t anchor_va = 0;

    /* --- misc --- */
    unsigned char key = 0;
    uint64_t off = 0;
    uint8_t *grown = NULL;

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

    /* --- locate first PF_X PT_LOAD --- */
    for (int i = 0; i < ehdr->e_phnum; ++i) {

        Elf64_Phdr *p = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)i * ehdr->e_phentsize);

        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) { 
            text_segment = p;
            text_seg_index = i;
            break;
        }
    }

    if (!text_segment) { 
        fprintf(stderr, "[!] could not find PF_X segment\n"); 
        goto exit; 
    }

    /* --- window: from after PHDR table (but not before segment) to stub start --- */
    encrypt_start_off = u64_max((uint64_t)ehdr->e_phoff + ph_size, (uint64_t)text_segment->p_offset);
    text_file_end = text_segment->p_offset + text_segment->p_filesz; // before extension

    if (encrypt_start_off < text_segment->p_offset || encrypt_start_off >= text_file_end) {
        fprintf(stderr, "[!] encrypt_start outside PF_X (0x%jx not in [0x%jx..0x%jx))\n",
                (uintmax_t)encrypt_start_off, (uintmax_t)text_segment->p_offset, (uintmax_t)text_file_end);
        goto exit;
    }

    /* --- computer link-time VAs --- */
    actual_entry_va = ehdr->e_entry;
    stub_va         = text_segment->p_vaddr + text_segment->p_filesz; // VA of stub start
    virt_start_va   = text_segment->p_vaddr + (encrypt_start_off - text_segment->p_offset);
    virt_end_va     = stub_va; // decrypt up to stub

    /* --- choose stub based on RWX --- */
    const bool text_is_rwx = (text_segment->p_flags & PF_W) != 0; // PF_X implied by selection

    if (text_is_rwx) {
        /* --- legacy RWX stub (no mprotect) --- */
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
            0x48, 0xFF, 0xC6,                   // 53: inc rsi
            0x48, 0x39, 0xD6,                   // 56: cmp rsi, rdx
            0x72, 0xF6,                         // 59: jb  -0x0A
            0x48, 0xB8,                         // 61: mov rax, imm64 (actual_entry)
            0,0,0,0,0,0,0,0,                    // 63: imm64 actual_entry
            0x48, 0x01, 0xD8,                   // 71: add rax, rbx
            0x5B,                               // 74: pop rbx
            0x5A,                               // 75: pop rdx
            0x5E,                               // 76: pop rsi
            0xFF, 0xE0                          // 77: jmp rax
        };

        /* --- prepare to place stub --- */
        stub_file_off = text_file_end;
        size_needed   = stub_file_off + sizeof(stub);

        /* --- if SHT would be overlapped by the inserted stub, move it forward --- */
        if (!relocate_sht(&data, &size, &ehdr, (size_t)stub_file_off, sizeof(stub))) 
            goto exit;

        if (size_needed > size) {
            if (!(grown = (uint8_t *)realloc(data, (size_t)size_needed))) { 
                fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
                goto exit; 
            } 

            memset(grown + size, 0x00, (size_t)(size_needed - size));
            data = grown; size = (size_t)size_needed; *p_data = data; *p_size = size;
            /* --- refresh views --- */
            ehdr = (Elf64_Ehdr *)data;
            phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
            text_segment = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)text_seg_index * ehdr->e_phentsize);       
        }

        /* --- patch immediates --- */
        srand((unsigned)time(NULL));
        key = (unsigned char)(rand() & 0xFF);
        anchor_va = stub_va + LEG_ANCHOR_DELTA;

        stub[LEG_OFF_KEY_IMM8] = key;
        memcpy(stub + LEG_OFF_ANCHOR_IMM64, &anchor_va,       sizeof(uint64_t));
        memcpy(stub + LEG_OFF_VSTART_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + LEG_OFF_VEND_IMM64,   &virt_end_va,     sizeof(uint64_t));
        memcpy(stub + LEG_OFF_ACTENT_IMM64, &actual_entry_va, sizeof(uint64_t));

        /* --- write stub --- */
        memcpy(data + stub_file_off, stub, sizeof(stub));

        /* --- extend segment so loader maps the stub --- */
        text_segment->p_filesz += sizeof(stub);
        text_segment->p_memsz  += sizeof(stub);

        /* --- set new entry and encrypt --- */
        ehdr->e_entry = stub_va;

        for (off = encrypt_start_off; off < stub_file_off; ++off) {
            data[off] ^= (uint8_t)key;
        }

        printf("[+] cryptor added (legacy RWX stub)\n");
        result = true;

    } else {
        /* --- PIE-safe mprotect stub --- */
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
            0x48, 0xFF, 0xC6,                   // 127: inc rsi
            0x48, 0x39, 0xD6,                   // 130: cmp rsi, rdx
            0x72, 0xF6,                         // 133: jb  -0x0A
            // mprotect(start..end, RX)
            0x48, 0x89, 0xF0,                   // 135: mov rax, rsi  (rax=end)
            0x48, 0xFF, 0xC8,                   // 138: dec rax
            0x48, 0x0D, 0xFF, 0x0F, 0x00, 0x00, // 141: or rax, 0xFFF
            0x48, 0xFF, 0xC0,                   // 147: inc rax
            0x48, 0x29, 0xF8,                   // 150: sub rax, rdi  (len)
            0x48, 0x89, 0xC6,                   // 153: mov rsi, rax  (len)
            0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00, // 156: mov rdx, 5 (PROT_RX)
            0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // 163: mov rax, 10 (SYS_mprotect)
            0x0F, 0x05,                         // 170: syscall
            // jump to original entry
            0x48, 0xB8,                         // 172: mov rax, imm64 (actual_entry)
            0,0,0,0,0,0,0,0,                    // 174: imm64 actual_entry
            0x48, 0x01, 0xD8,                   // 182: add rax, rbx  (apply slide)
            0x5B,                               // 185: pop rbx
            0x5A,                               // 186: pop rdx
            0x5E,                               // 187: pop rsi
            0x5F,                               // 188: pop rdi
            0xFF, 0xE0                          // 189: jmp rax
        };

        /* --- prepare to place stub --- */
        stub_file_off = text_file_end;
        size_needed   = stub_file_off + sizeof(stub);

        if (!relocate_sht(&data, &size, &ehdr, (size_t)stub_file_off, sizeof(stub))) 
            goto exit;

        if (size_needed > size) {
            if (!(grown = (uint8_t *)realloc(data, (size_t)size_needed))) { 
                fprintf(stderr, "[!] realloc failed: %s\n", strerror(errno)); 
                goto exit; 
            }
            
            memset(grown + size, 0x00, (size_t)(size_needed - size));
            data = grown; size = (size_t)size_needed; *p_data = data; *p_size = size;
            /* --- refresh views --- */
            ehdr = (Elf64_Ehdr *)data;
            phdr_base = (Elf64_Phdr *)(data + ehdr->e_phoff);
            text_segment = (Elf64_Phdr *)((uint8_t *)phdr_base + (size_t)text_seg_index * ehdr->e_phentsize);
        }

        /* --- patch immediates --- */
        srand((unsigned)time(NULL));
        key = (unsigned char)(rand() & 0xFF);
        anchor_va = stub_va + MP_ANCHOR_DELTA;

        memcpy(stub + MP_OFF_ANCHOR_IMM64,  &anchor_va,       sizeof(uint64_t));
        memcpy(stub + MP_OFF_VSTART1_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + MP_OFF_VEND1_IMM64,   &virt_end_va,     sizeof(uint64_t));
        memcpy(stub + MP_OFF_VSTART2_IMM64, &virt_start_va,   sizeof(uint64_t));
        memcpy(stub + MP_OFF_VEND2_IMM64,   &virt_end_va,     sizeof(uint64_t));
        stub[MP_OFF_KEY_IMM8] = key;
        memcpy(stub + MP_OFF_ACTENT_IMM64,  &actual_entry_va, sizeof(uint64_t));

        /* --- write stub --- */
        memcpy(data + stub_file_off, stub, sizeof(stub));

        /* --- extend segment so loader maps the stub --- */
        text_segment->p_filesz += sizeof(stub);
        text_segment->p_memsz  += sizeof(stub);

        /* --- set new entry and encrypt --- */
        ehdr->e_entry = stub_va;
        
        for (off = encrypt_start_off; off < stub_file_off; ++off) {
            data[off] ^= (uint8_t)key;
        }

        printf("[+] cryptor added (mprotect stub)\n");
        result = true;
    }

exit:
    /* --- ensure outputs reflect realloc --- */
    *p_data = data; *p_size = size;
    return result;
}
