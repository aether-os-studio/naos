#pragma once

#include <stdint.h>

#define SEEK_SET 0 /* Seek from beginning of file.  */
#define SEEK_CUR 1 /* Seek from current position.  */
#define SEEK_END 2 /* Seek from end of file.  */

typedef struct dirent
{
    char name[255];
    uint8_t type;
} dirent_t;
