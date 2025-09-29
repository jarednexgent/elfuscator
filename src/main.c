#include <stdio.h> 
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <elf.h>
#include "fileio.h"
#include "strip.h"
#include "spoof.h"
#include "dynsym.h"
#include "cryptor.h"
#include "dumps.h"

/* --- check if input is valid elf file --- */
static bool check_elf(const char *data) 
{
    const unsigned char *ident = (const unsigned char *)data;

    if (ident[EI_MAG0] != ELFMAG0 ||
        ident[EI_MAG1] != ELFMAG1 ||
        ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    
    return true;
}

static bool switch_endianness(char *data, size_t data_len)
{      
    if (!data || data_len < EI_DATA + 1)
        return false;

    unsigned char *ident = (unsigned char *)data;

    if (ident[EI_DATA] == ELFDATA2LSB) {
        ident[EI_DATA] = ELFDATA2MSB;
        printf("[+] endianness switched to big endian\n");
    } else if (ident[EI_DATA] == ELFDATA2MSB) {
        ident[EI_DATA] = ELFDATA2LSB;
        printf("[+] endianess switched to little endian\n");
    } else {
        fprintf(stderr, "[!] unknown or unsupported encoding\n");
        return false;
    }
    
    return true;
}

/* --- bytes 9-15 are padding and safe to mutate --- */
static bool randomize_ident_padding(char *data, size_t len) 
{
    if (!data || len < EI_NIDENT) 
        return false;

    unsigned char *ident_padding = (unsigned char *)data;
    
    srand((unsigned)time(NULL)); 

    for (int x = EI_PAD; x < EI_NIDENT; ++x) {
        ident_padding[x] = (unsigned char)(rand() & 0xFF);
    }

    printf("[+] e_ident padding bytes randomized\n");
    return true;
}


static void print_help(const char *program_name)
{
    printf("Usage:\n");
    printf("  %s -s <path-to-elf>   Strip section header table\n", program_name);
    printf("  %s -p <path-to-elf>   Spoof section header table\n", program_name);
    printf("  %s -y <path-to-elf>   Shuffle dynamic symbol names\n", program_name);
    printf("  %s -e <path-to-elf>   Switch endianness (ELFDATA2LSB <-> ELFDATA2MSB)\n", program_name);
    printf("  %s -r <path-to-elf>   Randomize padding bytes\n", program_name);
    printf("  %s -d <path-to-elf>   Disable core dumps\n", program_name);
    printf("  %s -c <path-to-elf>   Encrypt code segment\n", program_name);
    printf("  %s -h | --help        Show this help message\n", program_name);

}

int main(int argc, char **argv) {
    if (argc != 3) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    const char *option = argv[1];
    const char *elf_path = argv[2];
    size_t file_size = 0;
    char *file_data = NULL;
    bool success = false;

    if (!(file_data = read_file(elf_path, &file_size))) {
        fprintf(stderr, "[-] failed to read input file\n");
        goto exit;
    }

    if (!check_elf(file_data)) {
        fprintf(stderr, "[-] invalid ELF magic bytes\n");
        goto exit;
    }

    if (strcmp(option, "-s") == 0) {
        if (!strip_sections_table(file_data)) {
            fprintf(stderr, "[-] failed to remove section header table\n");
            goto exit;
        }
    } else if (strcmp(option, "-p") == 0) {
        if (!spoof_sections_table(&file_data, &file_size)) {
            fprintf(stderr, "[-] failed to insert spoofed sections table\n");
            goto exit;
        }
    } else if (strcmp(option, "-y") == 0) {
        if (!shuffle_dynsym_names(&file_data, &file_size)) {
            fprintf(stderr, "[-] failed to shuffle dynamic symbol names\n");
            goto exit;
        }
    } else if (strcmp(option, "-e") == 0) {
        if (!switch_endianness(file_data, file_size)) {
            fprintf(stderr, "[-] failed to switch endianness\n");
            goto exit;
        }
    } else if (strcmp(option, "-r") == 0) {
        if (!randomize_ident_padding(file_data, file_size)) {
            fprintf(stderr, "[-] failed to randomize e_ident padding bytes\n");
            goto exit;
        }
    } else if (strcmp(option, "-c") == 0) {
        if (!encrypt_code_segment((uint8_t **)&file_data, &file_size)) {
            fprintf(stderr, "[-] failed to encrypt code segment\n");
            goto exit;
        }
    } else if (strcmp(option, "-d") == 0) {
        if (!disable_dumps((uint8_t **)&file_data, &file_size)) {
            fprintf(stderr, "[-] failed to disable dumpable attribute\n");
            goto exit;
        }
    } else if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0) {
        print_help(argv[0]);
        goto exit;
        
    } else {
        fprintf(stderr, "[-] unknown option: %s\n", option);
        print_help(argv[0]);
        goto exit;
    }

    if (!write_file(elf_path, file_data, file_size)) {
        fprintf(stderr, "[-] failed to write output file\n");
        goto exit;
    }

    success = true;

exit:
    if (file_data) free(file_data);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}