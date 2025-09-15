#ifndef FILEIO_H
#define FILEIO_H

#include <stddef.h> 
#include <stdbool.h>

#define MAX_FILE_SIZE (50 * 1024 * 1024) // 50 MB

char *read_file(const char* path, size_t* out_size);
bool write_file(const char* path, char* buffer, size_t size);

#endif // FILEIO_H