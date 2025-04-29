#pragma once

#include <stdint.h>

#define SEEK_SET 0 /* Seek from beginning of file.  */
#define SEEK_CUR 1 /* Seek from current position.  */
#define SEEK_END 2 /* Seek from end of file.  */

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

#define __MLIBC_DIRENT_BODY  \
    long d_ino;              \
    long d_off;              \
    unsigned short d_reclen; \
    unsigned char d_type;    \
    char d_name[1024];

struct dirent
{
    __MLIBC_DIRENT_BODY
};