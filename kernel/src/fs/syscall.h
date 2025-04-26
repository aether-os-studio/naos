#pragma once

#include <libs/klibc.h>

struct iovec
{
    uint8_t *iov_base;
    uint64_t len;
};

uint64_t sys_open(const char *name, uint64_t mode, uint64_t flags);
uint64_t sys_close(uint64_t fd);
uint64_t sys_read(uint64_t fd, void *buf, uint64_t len);
uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len);
uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence);
uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg);
uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count);
uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count);
