#pragma once

#include <ctypes.h>

enum
{
    file_none,   // 未获取信息
    file_dir,    // 文件夹
    file_block,  // 块设备，如硬盘
    file_stream, // 流式设备，如终端
};

typedef struct dirent
{
    char name[255];
    uint8_t type;
} dirent_t;
