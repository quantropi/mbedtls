/*
 *  Public Key exchange moudle: quantropi MASQ KEM
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PK_C)
#include "mbedtls/error.h"
#include "ssl_misc.h"
#include "mbedtls/ssl.h"
#include "debug_internal.h"
#include "mbedtls/debug.h"
#include "mbedtls/q_masqds.h"
#include "mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define UNUSED(x) (void)(x)

#if defined(MBEDTLS_MASQ_PPK_C) || defined(MBEDTLS_MASQ_ML_C)
typedef enum 
{
    KEM_LEVEL1,
    KEM_LEVEL3,
    KEM_LEVEL5
} MASQ_KEM_LEVEL;
typedef struct MASQ_KEM_HANDLE_   *MASQ_KEM_handle;
typedef struct MASQ_RAND_HANDLE_  *MASQ_RAND_handle;
#if defined(MBEDTLS_MASQ_PPK_C)
#include "masq_kem_hppk.h"
#endif
#if defined(MBEDTLS_MASQ_ML_C)
#include "masq_kem_mlkem.h"
#endif

void  masqkem_destroy_key(mbedtls_ssl_handshake_params *handshake)
{
    if (handshake->qpkem_privkey != NULL) mbedtls_free(handshake->qpkem_privkey);
    if (handshake->qpkem_pubkey != NULL) mbedtls_free(handshake->qpkem_pubkey);
    if (handshake->qpkem_peerkey != NULL) mbedtls_free(handshake->qpkem_peerkey);
    handshake->qpkem_privkey = NULL;
    handshake->qpkem_pubkey = NULL;
    handshake->qpkem_peerkey = NULL;
#if defined(MBEDTLS_MASQ_PPK_C)
    if (handshake->qpkem_type == 1)
        masq_kem_hppk_free(handshake->qpkem_handle);
#endif
#if defined(MBEDTLS_MASQ_ML_C)
    if (handshake->qpkem_type == 0)
        masq_kem_mlkem_free(handshake->qpkem_handle);
#endif
}

int masqkem_decaps(uint8_t *shared_secret, mbedtls_ssl_handshake_params *handshake) {
    int ret = 0;

#if defined(MBEDTLS_MASQ_PPK_C)
    if (handshake->qpkem_type == 1)
        ret = masq_kem_hppk_decaps(handshake->qpkem_handle, handshake->qpkem_privkey, handshake->qpkem_peerkey, shared_secret);
#endif
#if defined(MBEDTLS_MASQ_ML_C)
    if (handshake->qpkem_type == 0)
        ret = masq_kem_mlkem_decaps(handshake->qpkem_handle, handshake->qpkem_privkey, handshake->qpkem_peerkey, shared_secret);
    MBEDTLS_SSL_DEBUG_MSG_MASQ("  . ML kem decap...ret:%d\n", ret);
#endif

    return ret;
}

static int masqkem_encaps(mbedtls_ssl_handshake_params *handshake, uint8_t *output) {
    int ret = 0;

#if defined(MBEDTLS_MASQ_PPK_C)
    if (handshake->qpkem_type == 1)
        ret = masq_kem_hppk_encaps(handshake->qpkem_handle, handshake->qpkem_peerkey, handshake->qpkem_shared_secret, output);
#endif
#if defined(MBEDTLS_MASQ_ML_C)
    if (handshake->qpkem_type == 0)
        ret = masq_kem_mlkem_encaps(handshake->qpkem_handle, handshake->qpkem_peerkey, handshake->qpkem_shared_secret, output);
    MBEDTLS_SSL_DEBUG_MSG_MASQ("  . ML kem encap...ret=%d\n",ret);
#endif

    return ret;
}

static int32_t rand_cf(MASQ_RAND_handle *rand_handle, int32_t rand_length,  uint8_t *rand_num)
{
    UNUSED(rand_handle);
    psa_generate_random(rand_num, rand_length);
    return 0;
}

static int32_t rand_seed_cf(MASQ_RAND_handle *rand_handle, uint8_t *seed, int32_t seed_length)
{
    UNUSED(rand_handle);
    psa_generate_random(seed, seed_length);
    return 0;
}

static int  masqkem_generate_key(mbedtls_ssl_handshake_params *handshake, uint16_t named_group)
{
    MASQ_KEM_handle *kem_handle;

    switch (named_group) {
#if defined(MBEDTLS_MASQ_ML_C)
        case MBEDTLS_SSL_OQS_TLS_GROUP_MLKEM512:
            kem_handle = masq_kem_mlkem_init(KEM_LEVEL1, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
            handshake->qpkem_type = 0;
            break;
        case MBEDTLS_SSL_OQS_TLS_GROUP_MLKEM768:
            kem_handle = masq_kem_mlkem_init(KEM_LEVEL3, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
            handshake->qpkem_type = 0;
            break;
        case MBEDTLS_SSL_OQS_TLS_GROUP_MLKEM1024:
            kem_handle = masq_kem_mlkem_init(KEM_LEVEL5, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
            handshake->qpkem_type = 0;
            break;
#endif
#if defined(MBEDTLS_MASQ_PPK_C)
        case MBEDTLS_SSL_QP_TLS_GROUP_QHPPKKEM1:
            kem_handle = masq_kem_hppk_init(KEM_LEVEL1, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
            handshake->qpkem_type = 1;
            break;
        case MBEDTLS_SSL_QP_TLS_GROUP_QHPPKKEM3:
            kem_handle = masq_kem_hppk_init(KEM_LEVEL3, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
            handshake->qpkem_type = 1;
            break;
        case MBEDTLS_SSL_QP_TLS_GROUP_QHPPKKEM5:
            kem_handle = masq_kem_hppk_init(KEM_LEVEL5, (MASQ_rand_callback_t)rand_cf, (MASQ_rand_seed_callback_t)rand_seed_cf, NULL);
             handshake->qpkem_type = 1;
           break;
#endif
        default:
            return 1;
    }
    MBEDTLS_SSL_DEBUG_MSG_MASQ("  . MASQ kem init (%x) ret handle:%p\n", named_group, kem_handle);

    if (kem_handle == NULL) {
        return 1;
    }

#if defined(MBEDTLS_MASQ_PPK_C)
    if (handshake->qpkem_type == 1) {
        handshake->qpkem_pubkey_len = masq_kem_hppk_public_key_length(kem_handle);
        handshake->qpkem_privkey_len = masq_kem_hppk_secret_key_length(kem_handle);
        handshake->qpkem_pubkey = mbedtls_calloc(1, handshake->qpkem_pubkey_len);
        handshake->qpkem_privkey = mbedtls_calloc(1, handshake->qpkem_privkey_len);
        if (handshake->qpkem_privkey == NULL || handshake->qpkem_pubkey == NULL) {
            if (handshake->qpkem_privkey != NULL) mbedtls_free(handshake->qpkem_privkey);
            if (handshake->qpkem_pubkey != NULL) mbedtls_free(handshake->qpkem_pubkey);
            masq_kem_hppk_free(kem_handle);
            return 1;
        }
        masq_kem_hppk_keypair(kem_handle, handshake->qpkem_pubkey, handshake->qpkem_privkey);
    }
#endif
#if defined(MBEDTLS_MASQ_ML_C)
    if (handshake->qpkem_type == 0) {
        handshake->qpkem_pubkey_len = masq_kem_mlkem_public_key_length(kem_handle);
        handshake->qpkem_privkey_len = masq_kem_mlkem_secret_key_length(kem_handle);
        handshake->qpkem_pubkey = mbedtls_calloc(1, handshake->qpkem_pubkey_len);
        handshake->qpkem_privkey = mbedtls_calloc(1, handshake->qpkem_privkey_len);
        if (handshake->qpkem_privkey == NULL || handshake->qpkem_pubkey == NULL) {
            if (handshake->qpkem_privkey != NULL) mbedtls_free(handshake->qpkem_privkey);
            if (handshake->qpkem_pubkey != NULL) mbedtls_free(handshake->qpkem_pubkey);
            masq_kem_mlkem_free(kem_handle);
            return 1;
        }
        masq_kem_mlkem_keypair(kem_handle, handshake->qpkem_pubkey, handshake->qpkem_privkey);
    }
#endif

    // generate the shared secret to be shared with client later by using KEM
    rand_cf(NULL, 32, handshake->qpkem_shared_secret);

    handshake->qpkem_handle = (void *)kem_handle;

    return 0;
}

int mbedtls_ssl_tls13_generate_and_write_qpkem_key_exchange(
    mbedtls_ssl_context *ssl,
    uint16_t named_group,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len)
{
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    masqkem_generate_key(handshake, named_group);

    if (end-buf < handshake->qpkem_pubkey_len) {
            return 1;
    }

    if (handshake->qpkem_server_client == 1) {
        // share kem public key with server
        memcpy(buf, handshake->qpkem_pubkey, handshake->qpkem_pubkey_len);
        *out_len = handshake->qpkem_pubkey_len;
    } else {
        // share encapsulated shared secret with client
        masqkem_encaps(handshake, buf);
#if defined(MBEDTLS_MASQ_PPK_C)
        if (handshake->qpkem_type == 1)
            *out_len = masq_kem_hppk_ciphertext_length(handshake->qpkem_handle);
#endif
#if defined(MBEDTLS_MASQ_ML_C)
        if (handshake->qpkem_type == 0)
            *out_len = masq_kem_mlkem_ciphertext_length(handshake->qpkem_handle);
#endif
    }

    return 0;
}

int mbedtls_ssl_tls13_read_public_qpkem_share(mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len)
{
    uint8_t *p = (uint8_t *) buf;
    const uint8_t *end = buf + buf_len;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Get size of the TLS opaque key_exchange field of the KeyShareEntry struct. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    uint16_t peerkey_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check if key size is consistent with given buffer length. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, peerkey_len);

    /* Store peer's ECDH/FFDH public key. */
    handshake->qpkem_peerkey = mbedtls_calloc(1, peerkey_len);
    if (handshake->qpkem_peerkey == NULL) return 1;

    handshake->qpkem_peerkey_len = peerkey_len;
    memcpy(handshake->qpkem_peerkey, p, peerkey_len);

    return 0;
}


#endif

#endif /* MBEDTLS_PK_C */
