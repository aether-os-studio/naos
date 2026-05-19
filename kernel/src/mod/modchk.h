#pragma once

#define NAOS_SIG_MAGIC                                                         \
    0x4E414F53 // ASCII "NAOS" (0x4E='N', 0x41='A', 0x4F='O', 0x53='S')

#define HASH_SHA256 1
#define SHA256_HASH_LEN 32
#define HASH_LEN SHA256_HASH_LEN

#define ECC_KEY_LEN 32                   // P-256 field element length in bytes
#define ECC_PUBKEY_LEN (2 * ECC_KEY_LEN) // X||Y = 64 bytes
#define ECC_SIG_LEN (2 * ECC_KEY_LEN)    // R||S = 64 bytes

#include <libs/klibc.h>
#include <mod/module.h>

struct module_signature {
    uint32_t magic;    // NAOS_SIG_MAGIC
    uint8_t hash_algo; // HASH_SHA256
    uint8_t sig_len;   // ECC_SIG_LEN
    uint8_t reserved[2];
    uint8_t signature[ECC_SIG_LEN]; // R||S (64 bytes)
} __attribute__((packed));          // 确保结构体没有填充

/**
 * 校验一个内核模块的签名
 * @param module 文件句柄
 * @return 校验是否成功 (校验已经被装载的模块加或参数为空会返回 false)
 */
bool module_verify_signature(module_t *modules);
