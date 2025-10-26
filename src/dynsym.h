#ifndef DYNSYM_H
#define DYNSYM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_SYMBOLS                  4096
#define MIN_SYMBOLS                  2
#define DERANGEMENT_MIN_ELEMENTS     (MIN_SYMBOLS)   // guard for minimal pool 
#define DERANGEMENT_PAIR_SIZE        2u              // special case for 2 elements 
#define ROTATION_MIN_STEP            1u              // prevent fixed points 
#define SHUFFLE_IMPORTS              1

bool shuffle_dynsym_names(char **p_data, size_t *p_size);

#endif // DYNSYM_H