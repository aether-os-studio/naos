#ifndef _ENDIAN_H
#define _ENDIAN_H 1

#include <stdint.h>

// 判断系统字节序
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER BIG_ENDIAN
#else
#error "Unknown byte order!"
#endif

// 16位字节序转换
static inline uint16_t __bswap_16(uint16_t x)
{
    return (x >> 8) | (x << 8);
}

// 32位字节序转换
static inline uint32_t __bswap_32(uint32_t x)
{
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >> 8) |
           ((x & 0x0000FF00) << 8) |
           ((x & 0x000000FF) << 24);
}

// 64位字节序转换
static inline uint64_t __bswap_64(uint64_t x)
{
    return ((x & 0xFF00000000000000) >> 56) |
           ((x & 0x00FF000000000000) >> 40) |
           ((x & 0x0000FF0000000000) >> 24) |
           ((x & 0x000000FF00000000) >> 8) |
           ((x & 0x00000000FF000000) << 8) |
           ((x & 0x0000000000FF0000) << 24) |
           ((x & 0x000000000000FF00) << 40) |
           ((x & 0x00000000000000FF) << 56);
}

// 恒等函数（用于原生字节序）
static inline uint16_t __uint16_identity(uint16_t x) { return x; }
static inline uint32_t __uint32_identity(uint32_t x) { return x; }
static inline uint64_t __uint64_identity(uint64_t x) { return x; }

// 主机字节序到网络字节序（大端）
#define htobe16(x) (BYTE_ORDER == LITTLE_ENDIAN ? __bswap_16(x) : __uint16_identity(x))
#define htobe32(x) (BYTE_ORDER == LITTLE_ENDIAN ? __bswap_32(x) : __uint32_identity(x))
#define htobe64(x) (BYTE_ORDER == LITTLE_ENDIAN ? __bswap_64(x) : __uint64_identity(x))

// 主机字节序到小端
#define htole16(x) (BYTE_ORDER == BIG_ENDIAN ? __bswap_16(x) : __uint16_identity(x))
#define htole32(x) (BYTE_ORDER == BIG_ENDIAN ? __bswap_32(x) : __uint32_identity(x))
#define htole64(x) (BYTE_ORDER == BIG_ENDIAN ? __bswap_64(x) : __uint64_identity(x))

// 网络字节序（大端）到主机字节序
#define be16toh(x) htobe16(x)
#define be32toh(x) htobe32(x)
#define be64toh(x) htobe64(x)

// 小端到主机字节序
#define le16toh(x) htole16(x)
#define le32toh(x) htole32(x)
#define le64toh(x) htole64(x)

#endif /* endian.h */
