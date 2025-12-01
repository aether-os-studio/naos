#pragma once

#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>

dev_input_event_t *regist_input_dev(const char *device_name,
                                    const char *sysfs_path,
                                    const char *uevent_append,
                                    event_bit_t event_bit);
