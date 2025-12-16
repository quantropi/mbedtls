/**
 * \file q_masqds.h
 */
#ifndef MBEDTLS_Q_MASQDS_H
#define MBEDTLS_Q_MASQDS_H
#include "mbedtls/private_access.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "mbedtls/ssl.h"

/**
 * \brief   The MASQ context structure.
 */
typedef struct _mbedtls_masqds_context {
    void *MBEDTLS_PRIVATE(handle);
    int MBEDTLS_PRIVATE(pubkey_len);
    int MBEDTLS_PRIVATE(prikey_len);
    char *MBEDTLS_PRIVATE(prikey);
    char *MBEDTLS_PRIVATE(pubkey);
} mbedtls_masqds_context;

void masqkem_destroy_key(mbedtls_ssl_handshake_params *handshake);
int masqkem_decaps(uint8_t *shared_secret, mbedtls_ssl_handshake_params *handshake);

#if defined(MBEDTLS_DEBUG_C)
#define MBEDTLS_SSL_DEBUG_MSG_MASQ(...) mbedtls_printf(__VA_ARGS__)
#else
#define MBEDTLS_SSL_DEBUG_MSG_MASQ(...)
#endif

#ifdef __cplusplus
}
#endif

#endif /* masqds.h */