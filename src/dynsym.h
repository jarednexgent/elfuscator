#ifndef DYNSYM_H
#define DYNSYM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_SYMBOLS 4096
#define DYNSYM_DUPLICATE 1
#define SHUFFLE_IMPORTS 1

bool shuffle_dynsym_names(char **p_data, size_t *p_size);

#endif // DYNSYM_H