#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <stddef.h>
#include <stdbool.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

bool encrypt_code_segment(uint8_t **p_data, size_t *p_size);

#endif // CRYPTOR_H