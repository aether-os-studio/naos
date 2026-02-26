#include "os-interface.h"

#include <libs/aether/mm.h>

#define STUBBED                                                                \
    {                                                                          \
        ASSERT(!"unimplemented");                                              \
    }

void libspdm_aead_free(void *context) {}

#define SG_AEAD_AAD 0
#define SG_AEAD_TEXT 1
#define SG_AEAD_SIG 2
// Number of fields in AEAD scatterlist
#define SG_AEAD_LEN 3

int libspdm_aead(const uint8_t *key, size_t key_size, const uint8_t *iv,
                 size_t iv_size, const uint8_t *a_data, size_t a_data_size,
                 const uint8_t *data_in, size_t data_in_size,
                 const uint8_t *tag, size_t tag_size, uint8_t *data_out,
                 size_t *data_out_size, bool enc, char const *alg) {
    return -ENODEV;
}

// Wrapper to make look like libspdm
bool libspdm_aead_gcm_prealloc(void **context) { return false; }

bool libspdm_aead_aes_gcm_encrypt_prealloc(
    void *context, const uint8_t *key, size_t key_size, const uint8_t *iv,
    size_t iv_size, const uint8_t *a_data, size_t a_data_size,
    const uint8_t *data_in, size_t data_in_size, uint8_t *tag_out,
    size_t tag_size, uint8_t *data_out, size_t *data_out_size) {
    return false;
}

bool libspdm_aead_aes_gcm_decrypt_prealloc(
    void *context, const uint8_t *key, size_t key_size, const uint8_t *iv,
    size_t iv_size, const uint8_t *a_data, size_t a_data_size,
    const uint8_t *data_in, size_t data_in_size, const uint8_t *tag,
    size_t tag_size, uint8_t *data_out, size_t *data_out_size) {
    return false;
}

void *libspdm_hmac_sha256_new(void) { return NULL; }

void libspdm_hmac_sha256_free(void *hmac_sha256_ctx) {}

bool libspdm_hmac_sha256_set_key(void *hmac_sha256_ctx, const uint8_t *key,
                                 size_t key_size) {
    return false;
}

bool libspdm_hmac_sha256_duplicate(const void *hmac_sha256_ctx,
                                   void *new_hmac_sha256_ctx) {
    return false;
}

bool libspdm_hmac_sha256_update(void *hmac_sha256_ctx, const void *data,
                                size_t data_size) {
    return false;
}

bool libspdm_hmac_sha256_final(void *hmac_sha256_ctx, uint8_t *hmac_value) {
    return false;
}

bool libspdm_hmac_sha256_all(const void *data, size_t data_size,
                             const uint8_t *key, size_t key_size,
                             uint8_t *hmac_value) {
    return false;
}

bool libspdm_check_crypto_backend(void) {
    nv_printf(NV_DBG_ERRORS, "libspdm_check_crypto_backend: Error - libspdm "
                             "expects LKCA but found stubs!\n");
    return false;
}

bool libspdm_x509_verify_cert_chain(const uint8_t *root_cert,
                                    size_t root_cert_length,
                                    const uint8_t *cert_chain,
                                    size_t cert_chain_length) STUBBED;

bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                           size_t cert_chain_length,
                                           const int32_t cert_index,
                                           const uint8_t **cert,
                                           size_t *cert_length) STUBBED;

bool libspdm_rsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **rsa_context) {
    ASSERT(false);
    return false;
}

bool libspdm_ec_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                         void **ec_context) {
    return false;
}

bool libspdm_x509_verify_cert(const uint8_t *cert, size_t cert_size,
                              const uint8_t *ca_cert,
                              size_t ca_cert_size) STUBBED;

bool libspdm_rsa_pss_sign(void *rsa_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          uint8_t *signature, size_t *sig_size) STUBBED;

bool libspdm_ecdsa_sign(void *ec_context, size_t hash_nid,
                        const uint8_t *message_hash, size_t hash_size,
                        uint8_t *signature, size_t *sig_size) STUBBED;

void libspdm_rsa_free(void *rsa_context) {}
void libspdm_ec_free(void *ec_context) {}

bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size) {
    return false;
}

bool libspdm_ecdsa_verify(void *ec_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          const uint8_t *signature, size_t sig_size) STUBBED;

bool libspdm_asn1_get_tag(uint8_t **ptr, const uint8_t *end, size_t *length,
                          uint32_t tag) STUBBED;

bool libspdm_x509_get_tbs_cert(const uint8_t *cert, size_t cert_size,
                               uint8_t **tbs_cert, size_t *tbs_cert_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_version(const uint8_t *cert, size_t cert_size,
                              size_t *version) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_serial_number(const uint8_t *cert, size_t cert_size,
                                    uint8_t *serial_number,
                                    size_t *serial_number_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_issuer_name(const uint8_t *cert, size_t cert_size,
                                  uint8_t *cert_issuer, size_t *issuer_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_issuer_common_name(const uint8_t *cert, size_t cert_size,
                                         char *common_name,
                                         size_t *common_name_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_issuer_orgnization_name(const uint8_t *cert,
                                              size_t cert_size,
                                              char *name_buffer,
                                              size_t *name_buffer_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_signature_algorithm(const uint8_t *cert, size_t cert_size,
                                          uint8_t *oid, size_t *oid_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_extension_data(const uint8_t *cert, size_t cert_size,
                                     const uint8_t *oid, size_t oid_size,
                                     uint8_t *extension_data,
                                     size_t *extension_data_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_validity(const uint8_t *cert, size_t cert_size,
                               uint8_t *from, size_t *from_size, uint8_t *to,
                               size_t *to_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_key_usage(const uint8_t *cert, size_t cert_size,
                                size_t *usage) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_extended_key_usage(const uint8_t *cert, size_t cert_size,
                                         uint8_t *usage, size_t *usage_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_extended_basic_constraints(
    const uint8_t *cert, size_t cert_size, uint8_t *basic_constraints,
    size_t *basic_constraints_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_set_date_time(char const *date_time_str, void *date_time,
                                size_t *date_time_size) {
    ASSERT(false);
    return false;
}

int32_t libspdm_x509_compare_date_time(const void *date_time1,
                                       const void *date_time2) {
    ASSERT(false);
    return -3;
}

bool libspdm_gen_x509_csr(size_t hash_nid, size_t asym_nid,
                          uint8_t *requester_info, size_t requester_info_length,
                          void *context, char *subject_name, size_t *csr_len,
                          uint8_t **csr_pointer) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_subject_name(const uint8_t *cert, size_t cert_size,
                                   uint8_t *cert_subject,
                                   size_t *subject_size) {
    ASSERT(false);
    return false;
}

bool libspdm_x509_get_common_name(const uint8_t *cert, size_t cert_size,
                                  char *common_name, size_t *common_name_size) {
    ASSERT(false);
    return false;
}

void *libspdm_sha256_new(void) { return NULL; }

void libspdm_sha256_free(void *sha256_ctx) {}

bool libspdm_sha256_init(void *sha256_context) STUBBED;
bool libspdm_sha256_duplicate(const void *sha256_context,
                              void *new_sha256_context) {
    return false;
}
bool libspdm_sha256_update(void *sha256_context, const void *data,
                           size_t data_size) STUBBED;
bool libspdm_sha256_final(void *sha256_context, uint8_t *hash_value) STUBBED;

void *libspdm_sha384_new(void) { return NULL; }

void libspdm_sha384_free(void *sha384_ctx) {}

bool libspdm_sha384_init(void *sha384_context) STUBBED;
bool libspdm_sha384_duplicate(const void *sha384_context,
                              void *new_sha384_context) {
    return false;
}
bool libspdm_sha384_update(void *sha384_context, const void *data,
                           size_t data_size) STUBBED;
bool libspdm_sha384_final(void *sha384_context, uint8_t *hash_value) STUBBED;

bool libspdm_sha256_hash_all(const void *data, size_t data_size,
                             uint8_t *hash_value) STUBBED;

bool libspdm_sha384_hash_all(const void *data, size_t data_size,
                             uint8_t *hash_value) STUBBED;

void *libspdm_rsa_new(void) { return NULL; }

/* RSA key Tags Definition used in libspdm_rsa_set_key() function for key
 * component identification.
 */
typedef enum {
    LIBSPDM_RSA_KEY_N,    /*< RSA public Modulus (N)*/
    LIBSPDM_RSA_KEY_E,    /*< RSA public exponent (e)*/
    LIBSPDM_RSA_KEY_D,    /*< RSA Private exponent (d)*/
    LIBSPDM_RSA_KEY_P,    /*< RSA secret prime factor of Modulus (p)*/
    LIBSPDM_RSA_KEY_Q,    /*< RSA secret prime factor of Modules (q)*/
    LIBSPDM_RSA_KEY_DP,   /*< p's CRT exponent (== d mod (p - 1))*/
    LIBSPDM_RSA_KEY_DQ,   /*< q's CRT exponent (== d mod (q - 1))*/
    LIBSPDM_RSA_KEY_Q_INV /*< The CRT coefficient (== 1/q mod p)*/
} libspdm_rsa_key_tag_t;

bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, size_t bn_size) {
    return false;
}

bool libspdm_hkdf_sha256_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size) STUBBED;

bool libspdm_aead_aes_gcm_encrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  uint8_t *tag_out, size_t tag_size,
                                  uint8_t *data_out,
                                  size_t *data_out_size) STUBBED;

bool libspdm_aead_aes_gcm_decrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  const uint8_t *tag, size_t tag_size,
                                  uint8_t *data_out,
                                  size_t *data_out_size) STUBBED;

void *libspdm_ec_new_by_nid(size_t nid) STUBBED;

bool libspdm_ec_generate_key(void *ec_context, uint8_t *public_data,
                             size_t *public_size) STUBBED;

bool libspdm_ec_compute_key(void *ec_context, const uint8_t *peer_public,
                            size_t peer_public_size, uint8_t *key,
                            size_t *key_size) STUBBED;

bool libspdm_hkdf_sha256_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size) STUBBED;

bool libspdm_hkdf_sha384_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size) STUBBED;

bool libspdm_hkdf_sha384_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size) STUBBED;

void *libspdm_hmac_sha384_new() STUBBED;
void libspdm_hmac_sha384_free(void *hmac_sha384_ctx) STUBBED;
bool libspdm_hmac_sha384_set_key(void *hmac_sha384_ctx, const uint8_t *key,
                                 size_t key_size) STUBBED;
bool libspdm_hmac_sha384_duplicate(const void *hmac_sha384_ctx,
                                   void *new_hmac_sha384_ctx) STUBBED;
bool libspdm_hmac_sha384_update(void *hmac_sha384_ctx, const void *data,
                                size_t data_size) STUBBED;
bool libspdm_hmac_sha384_final(void *hmac_sha384_ctx,
                               uint8_t *hmac_value) STUBBED;
bool libspdm_hmac_sha384_all(const void *data, size_t data_size,
                             const uint8_t *key, size_t key_size,
                             uint8_t *hmac_value) STUBBED;

static uint32_t simple_rand() {
    tm time;
    time_read(&time);
    uint32_t seed = mktime(&time);
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return seed;
}

bool libspdm_random_bytes(uint8_t *output, size_t size) {
    size_t read = 0;

    while (read < size) {
        uint8_t byte = (uint8_t)simple_rand();
        memcpy(output + read, &byte, 1);
        read++;
    }

    return true;
}

// This is specifically allowed by spdm
bool libspdm_random_seed(const uint8_t *seed, size_t seed_size) { return true; }
