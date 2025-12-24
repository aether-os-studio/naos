#pragma once

#include <libs/klibc.h>
#include <net/socket.h>

struct bpf_vm {
    uint32_t A;          // 累加器
    uint32_t X;          // 索引寄存器
    uint32_t M[16];      // 临时存储 (scratch memory)
    uint32_t pc;         // 程序计数器
    const uint8_t *data; // 数据包指针
    uint32_t len;        // 数据包长度
};

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

#define BPF_SIZE(code) ((code) & 0x18)
#define BPF_W 0x00 // 32位
#define BPF_H 0x08 // 16位
#define BPF_B 0x10 // 8位

#define BPF_MODE(code) ((code) & 0xe0)
#define BPF_IMM 0x00 // 立即数
#define BPF_ABS 0x20 // 绝对偏移
#define BPF_IND 0x40 // 间接偏移
#define BPF_MEM 0x60 // 临时存储
#define BPF_LEN 0x80 // 包长度
#define BPF_MSH 0xa0 // IP头长度

#define BPF_OP(code) ((code) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0

#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40

#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K 0x00 // 常量
#define BPF_X 0x08 // X寄存器

#define BPF_RVAL(code) ((code) & 0x18)
#define BPF_A 0x10

#define BPF_MISCOP(code) ((code) & 0xf8)
#define BPF_TAX 0x00 // A -> X
#define BPF_TXA 0x80 // X -> A

// 主机字节序到网络字节序
#define htonl(l)                                                               \
    ((((l) & 0xFF) << 24) | (((l) & 0xFF00) << 8) | (((l) & 0xFF0000) >> 8) |  \
     (((l) & 0xFF000000) >> 24))
#define htons(s) ((((s) & 0xFF) << 8) | (((s) & 0xFF00) >> 8))

// 网络字节序到主机字节序
#define ntohl(l) htonl((l))
#define ntohs(s) htons((s))

/*
 * 安全读取数据包内容
 */
static inline uint32_t bpf_read_word(const uint8_t *data, uint32_t len,
                                     uint32_t offset) {
    if (offset + 4 > len)
        return 0;
    return ntohl(*(uint32_t *)(data + offset));
}

static inline uint16_t bpf_read_half(const uint8_t *data, uint32_t len,
                                     uint32_t offset) {
    if (offset + 2 > len)
        return 0;
    return ntohs(*(uint16_t *)(data + offset));
}

static inline uint8_t bpf_read_byte(const uint8_t *data, uint32_t len,
                                    uint32_t offset) {
    if (offset >= len)
        return 0;
    return data[offset];
}

int bpf_validate(const struct sock_filter *prog, int len);
uint32_t bpf_run(const struct sock_filter *prog, int proglen,
                 const uint8_t *data, uint32_t datalen);
