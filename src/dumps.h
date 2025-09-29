#ifndef DUMPS_H
#define DUMPS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

bool disable_dumps(uint8_t **p_data, size_t *p_size);

#endif // DUMPS_H