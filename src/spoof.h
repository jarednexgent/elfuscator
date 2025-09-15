#ifndef SPOOF_H
#define SPOOF_H

#include <stddef.h>
#include <stdbool.h>

#define SECTION_ALIGN 16

bool spoof_section_headers(char** p_data, size_t* p_data_len); 
                              
#endif // SPOOF_H