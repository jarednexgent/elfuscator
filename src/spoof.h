#ifndef SPOOF_H
#define SPOOF_H

#include <stddef.h>
#include <stdbool.h>

#define SECTION_ALIGNMENT_BYTES         16u
#define INIT_OVERLAP_ENTRY_BYTES        1u     
#define FINI_SPOOF_MIN_BYTES            8u
#define SHSTRTAB_MAX_CAPACITY           256u
#define STRTAB_ALIGN                    1u

bool spoof_sections_table(char** p_data, size_t* p_data_len); 
                              
#endif // SPOOF_H