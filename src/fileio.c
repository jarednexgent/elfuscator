#include <stdio.h>   
#include <stdlib.h> 
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "fileio.h"

char *read_file(const char *path, size_t *out_size) 
{
    if (!path || !out_size)
        return NULL;

    FILE *file = NULL;
    char *buffer = NULL;
    long size = 0;

    *out_size = 0;

    if (!(file = fopen(path, "rb"))) {
        fprintf(stderr, "[!] fopen failed: %s\n", strerror(errno));
        goto exit;
    }

    if (fseek(file, 0, SEEK_END) || (size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET)) {
        fprintf(stderr, "[!] failed to determine file size or rewind: %s\n", strerror(errno));
        goto exit;
    }

    if (!(buffer = malloc((size_t)size))) {
        fprintf(stderr, "[!] malloc(%ld) failed: %s\n", size, strerror(errno));
        goto exit;
    }

    if (fread(buffer, 1, size, file) != (size_t)size) {
        fprintf(stderr, "[!] fread failed: %s\n", strerror(errno));
        free(buffer);
        buffer = NULL;
        goto exit;
    }

    *out_size = (size_t)size;

exit:
    if (file) fclose(file);
    return buffer;
}

bool write_file(const char *path, char *buffer, size_t size) 
{
    if (!path || !buffer || size == 0)
        return false;
    
    FILE *file = NULL;
    bool result = false; 

    if (!(file = fopen(path, "wb"))) {
        fprintf(stderr, "[!] fopen failed: %s\n", strerror(errno));
        goto exit;
    }

    if (fwrite(buffer, 1, size, file) != size) {
        fprintf(stderr, "[!] fwrite failed: %s\n", strerror(errno));
        goto exit;
    }

    if (fflush(file) != 0 || ferror(file)) {
        fprintf(stderr, "[!] fflush/ferror failed: %s\n", strerror(errno));
        goto exit;
    }

    result = true;

exit:
    if (fclose(file) != 0) {
        fprintf(stderr, "[!] fclose failed: %s\n", strerror(errno));
        result = false;
    }

    return result;
}
