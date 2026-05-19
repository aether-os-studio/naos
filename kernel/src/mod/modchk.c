#include <libs/tinycrypt/constants.h>
#include <libs/tinycrypt/ecc.h>
#include <libs/tinycrypt/ecc_dsa.h>
#include <libs/tinycrypt/sha256.h>
#include <drivers/logger.h>
#include "modchk.h"

static bool verify_impletment(module_t *modules) {
    if (modules->size < sizeof(struct module_signature)) {
        serial_fprintk("module file too small to contain signature info.\n");
        return false;
    }
    size_t data_len_to_hash = modules->size - sizeof(struct module_signature);
    struct module_signature *sig_info =
        (struct module_signature *)(modules->data + data_len_to_hash);
    if (sig_info->magic != NAOS_SIG_MAGIC) {
        serial_fprintk(
            "invalid signature magic 0x%X. Unsigned or corrupted module.\n",
            sig_info->magic);
        return false;
    }
    if (sig_info->hash_algo != HASH_SHA256) {
        serial_fprintk("unsupported hash algorithm: %u.\n",
                       sig_info->hash_algo);
        return false;
    }
    if (sig_info->sig_len != ECC_SIG_LEN) {
        serial_fprintk(
            "invalid signature length: %u. Expected %u for ECC P-256.\n",
            sig_info->sig_len, ECC_SIG_LEN);
        return false;
    }
    uint8_t calculated_hash[HASH_LEN];
    struct tc_sha256_state_struct s;
    if (tc_sha256_init(&s) != TC_CRYPTO_SUCCESS) {
        serial_fprintk("SHA256 initialization failed.\n");
        return false;
    }
    if (tc_sha256_update(&s, modules->data, data_len_to_hash) !=
        TC_CRYPTO_SUCCESS) {
        serial_fprintk("SHA256 update failed.\n");
        return false;
    }
    if (tc_sha256_final(calculated_hash, &s) != TC_CRYPTO_SUCCESS) {
        serial_fprintk("SHA256 finalization failed.\n");
        return false;
    }

    uint8_t *signature_data = sig_info->signature;

    uint8_t *pub =
#ifdef CONFIG_MODULE_VERIFY
        naos_signing_key_pub;
#else
        NULL;
#endif

    // 去除 0x04 || X || Y (65), 保留原始签名头
    if (pub[0] == 0x04) {
        pub += 1;
    }

    // uECC_verify(public_key, hash, hash_len, signature, curve)
    int result = uECC_verify(pub,             // 公钥 (X || Y)
                             calculated_hash, // 哈希值
                             HASH_LEN,        // 哈希长度 (32)
                             signature_data,  // 签名 (R || S)
                             uECC_secp256r1() // P-256 曲线上下文
    );

    // uECC_verify 成功返回 1，失败返回 0
    if (result == 1) {
        return true;
    }
    serial_fprintk("%s: module signature verification failed (err=%d): "
                   "signature not trusted.\n",
                   modules->path, result);
    return false;
}

bool module_verify_signature(module_t *modules) {
#ifdef CONFIG_MODULE_VERIFY
    if (modules == NULL || modules->is_use) {
        return false;
    }
    return verify_impletment(modules);
#else
    return true;
#endif
}
