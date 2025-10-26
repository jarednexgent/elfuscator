#ifndef TRACERS_H
#define TRACERS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

bool disable_tracers(uint8_t **p_data, size_t *p_size);

#endif // TRACERS_H