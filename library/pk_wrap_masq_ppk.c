/*
 *  Public Key abstraction layer: wrapper functions for quantropi MASQ
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/q_masqds.h"
#include "mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define UNUSED(x) (void)(x)

#if defined(MBEDTLS_MASQ_PPK_C)
#define MASQ_DS_ghppk
#include "masq_ds.h"

#if !defined(MBEDTLS_USE_MASQ_BN)
int q_bn_clear(mbedtls_mpi *a);
void masq_use_mbedtls_bn(void)
{   
    mbedtls_mpi a;
    q_bn_clear(&a);
}
#endif

#define DS_SEED_LEN 128

unsigned char seed_hdl[DS_SEED_LEN];

static int masqds_rand_cf(MASQ_RAND_handle rand_handle, int rand_length,  uint8_t *rand_num)
{
    if (rand_num == NULL) return -1;

    for (int i = 0; i < rand_length; i++)
        if (rand_handle != NULL) {
            rand_num[i] = ((uint8_t *)rand_handle)[i%DS_SEED_LEN];
        } else {
            rand_num[i] = rand() & 0xff;
        }

    return 0;
}

static int masqds_rand_seed_cf(MASQ_RAND_handle rand_handle, uint8_t *seed, int seed_length)
{
    if (seed==NULL || seed_length==0) return -1;

    memcpy((void *)rand_handle, (void *)seed, seed_length);

    return 0;
}

static int masqds_can_do_1(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_MASQDS1;
}
static int masqds_can_do_3(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_MASQDS3;
}
static int masqds_can_do_5(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_MASQDS5;
}

static size_t masqds_get_bitlen(mbedtls_pk_context *pk)
{
    size_t keylen;
    mbedtls_masqds_context *ctx = (mbedtls_masqds_context *) pk->pk_ctx;
    MASQ_DS_handle *ds_handle = (MASQ_DS_handle *) ctx->handle;

    keylen = (size_t)MASQ_DS_public_key_length(ds_handle) * 8;

    return keylen;
}

static int masqds_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret;
    const mbedtls_masqds_context *ctx = (const mbedtls_masqds_context *) pk->pk_ctx;

    UNUSED(md_alg);

    ret = MASQ_DS_verify((MASQ_DS_handle *)(ctx->handle), (uint8_t *)(ctx->pubkey), (uint8_t *)msg, msg_len, (uint8_t *)sig, (int32_t)sig_len, NULL, 0);

    return ret;
}

static int masqds_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *msg, size_t msg_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    const mbedtls_masqds_context *ctx;
    unsigned char seed_orig[DS_SEED_LEN] = {0};

    UNUSED(md_alg);

    f_rng(p_rng, seed_orig, DS_SEED_LEN);

    ctx = (const mbedtls_masqds_context *) pk->pk_ctx;

    *sig_len = MASQ_DS_signature_length((MASQ_DS_handle *)(ctx->handle));
    if (sig_size < *sig_len) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    MASQ_DS_seed((MASQ_DS_handle *)(ctx->handle), seed_orig, DS_SEED_LEN);    

    ret = MASQ_DS_sign((MASQ_DS_handle *)(ctx->handle), (uint8_t *)(ctx->prikey), (uint8_t *)msg, msg_len, (uint8_t *)sig, (int32_t *)sig_len, NULL, 0);

    return ret;
}

static void *masqds_alloc_wrap(MASQ_DS_LEVEL level) 
{
    MASQ_DS_handle * ds_handle;
    mbedtls_masqds_context *q_ctx;

    q_ctx = (mbedtls_masqds_context *)mbedtls_calloc(1, sizeof(mbedtls_masqds_context));
    if (q_ctx == NULL)  return NULL;

    ds_handle = MASQ_DS_init(level, (MASQ_rand_callback_t)masqds_rand_cf, (MASQ_rand_seed_callback_t)masqds_rand_seed_cf, (MASQ_RAND_handle)seed_hdl);
    if (ds_handle == NULL) {
        mbedtls_free(q_ctx);
        return NULL;
    }        

    q_ctx->handle = ds_handle;
    q_ctx->prikey_len = MASQ_DS_private_key_length(ds_handle);
    q_ctx->pubkey_len = MASQ_DS_public_key_length(ds_handle);
    q_ctx->prikey = mbedtls_calloc(1, q_ctx->prikey_len);
    q_ctx->pubkey = mbedtls_calloc(1, q_ctx->pubkey_len);
    if (q_ctx->prikey == NULL || q_ctx->pubkey == NULL) {
        if (q_ctx->prikey != NULL) mbedtls_free(q_ctx->prikey);
        if (q_ctx->pubkey != NULL) mbedtls_free(q_ctx->pubkey);
        MASQ_DS_free(ds_handle);
        return NULL;
    }

    return ((void *)q_ctx);
}
static void *masqds_alloc_wrap_1(void)
{
    return masqds_alloc_wrap(DS_LEVEL1);
}
static void *masqds_alloc_wrap_3(void)
{
    return masqds_alloc_wrap(DS_LEVEL3);
}
static void *masqds_alloc_wrap_5(void)
{
    return masqds_alloc_wrap(DS_LEVEL5);
}

static void masqds_free_wrap(void *ctx)
{
    mbedtls_masqds_context * q_ctx = ctx;
    if (ctx != NULL) {
        if (q_ctx->prikey != NULL) mbedtls_free(q_ctx->prikey);
        if (q_ctx->pubkey != NULL) mbedtls_free(q_ctx->pubkey);
        MASQ_DS_free((MASQ_DS_handle *)(q_ctx->handle));
        mbedtls_free(ctx);
    }
}

// need to define this
const mbedtls_pk_info_t mbedtls_masqds1_info = {
    .type = MBEDTLS_PK_MASQDS1,
    .name = "qghppkds1",
    .get_bitlen = masqds_get_bitlen,
    .can_do = masqds_can_do_1,
    .verify_func = masqds_verify_wrap,
    .sign_func = masqds_sign_wrap,
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = masqds_alloc_wrap_1,
    .ctx_free_func = masqds_free_wrap,
    .debug_func = NULL,
};
// need to define this
const mbedtls_pk_info_t mbedtls_masqds3_info = {
    .type = MBEDTLS_PK_MASQDS3,
    .name = "qghppkds3",
    .get_bitlen = masqds_get_bitlen,
    .can_do = masqds_can_do_3,
    .verify_func = masqds_verify_wrap,
    .sign_func = masqds_sign_wrap,
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = masqds_alloc_wrap_3,
    .ctx_free_func = masqds_free_wrap,
    .debug_func = NULL,
};
// need to define this
const mbedtls_pk_info_t mbedtls_masqds5_info = {
    .type = MBEDTLS_PK_MASQDS5,
    .name = "qghppkds5",
    .get_bitlen = masqds_get_bitlen,
    .can_do = masqds_can_do_5,
    .verify_func = masqds_verify_wrap,
    .sign_func = masqds_sign_wrap,
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = masqds_alloc_wrap_5,
    .ctx_free_func = masqds_free_wrap,
    .debug_func = NULL,
};

#endif

#endif /* MBEDTLS_PK_C */
