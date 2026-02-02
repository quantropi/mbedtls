/*
* This compute unit is to implement masq_bn util wrap APIs
* Defined at common/masq_bn_util.h
* Mapping MbedTLS to MASQ_BN Util functions
*/
#include <stdlib.h>
#include <string.h>
#include "mbedtls/bignum.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#if !defined(MBEDTLS_USE_MASQ_BN)

typedef struct mbedtls_mpi   *qbn;

typedef struct MASQ_RAND_HANDLE_   *MASQ_RAND_handle;

#define MASQ_MPPK_BASE_SIZE_BYTES 8
#define MASQ_MPPK_BASE_SIZE_BITS 64
#define RUN_RANDOM_LOOP 10

//Initialize a, and set to 0
#define q_bn_init(a)  a=q_bn_init_r();

//Initialize p and set its value from a null terminated C string in base radix
// If the string is a correct base radix, the function returns 0. If an error occurs it returns -1
#define q_bn_init_p(p, ptr, radix) p=q_bn_init_p_r((ptr), (radix));

//Initialize a, with limb space and set the initial numeric value from b.
#define q_bn_init_with_int(a, b)   a=q_bn_init_with_int_r(b); 

/**
 * Callback function type to generate random 
 * Caller should always seed rand generator and allocate enough memory
 *
 * @param[in] rand_handle handle for random generator.
 * @param[in] rand_length The number of random required in byte.
 * @param[out] rand The generated random  represented as a byte string.
 * @return The number of random generated in bytes, the value should equal rand_length if success. 
 *         Otherwise, return -1 if fail
*/
typedef int32_t (* MASQ_rand_callback_t)(MASQ_RAND_handle rand_handle, int32_t rand_length,  uint8_t *rand);

qbn q_bn_init_r(void)
{
    int ret = 0;
    qbn a = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(a == NULL) return NULL;
    mbedtls_mpi_init((mbedtls_mpi *)a);
    ret = mbedtls_mpi_lset((mbedtls_mpi *)a, (mbedtls_mpi_sint)0);
    if (ret == 0) {
        return a;
    } else {
        mbedtls_mpi_free((mbedtls_mpi *)a);
        mbedtls_free(a);
        return NULL;
    }
}

qbn q_bn_init_with_int_r(int b)
{
    int ret = 0;
    qbn a = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(a == NULL) return NULL;
    mbedtls_mpi_init((mbedtls_mpi *)a);
    ret = mbedtls_mpi_lset((mbedtls_mpi *)a, (mbedtls_mpi_sint)b);
    if (ret == 0) {
        return a;
    } else {
        mbedtls_mpi_free((mbedtls_mpi *)a);
        mbedtls_free(a);
        return NULL;
    }
}

qbn q_bn_init_p_r(const char* b, int radix)
{
    int ret = 0;
    qbn a = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(a == NULL) return NULL;
    mbedtls_mpi_init((mbedtls_mpi *)a);
    ret = mbedtls_mpi_read_string((mbedtls_mpi *)a, radix, b);
    if (ret == 0) {
        return a;
    } else {
        mbedtls_mpi_free((mbedtls_mpi *)a);
        mbedtls_free(a);
        return NULL;
    }
}

int q_bn_set_zero(qbn a)
{
    int ret = 0;
    ret = mbedtls_mpi_lset((mbedtls_mpi *)a, (mbedtls_mpi_sint)0);
    return ret;
}

int q_bn_set_one(qbn a)
{
    int ret = 0;
    ret = mbedtls_mpi_lset((mbedtls_mpi *)a, (mbedtls_mpi_sint)1);
    return ret;
}

/* a = base mod p, 0 <= a < base if p > 0 */
int q_bn_mod(qbn a, qbn base, qbn p)
{
    int ret = 0;
    if(p->private_s == -1){
        p->private_s = 1;
        ret = mbedtls_mpi_mod_mpi((mbedtls_mpi *)a, (const mbedtls_mpi *)base, (const mbedtls_mpi *)p);
        a->private_s = -1;
        if(mbedtls_mpi_cmp_mpi(a, p) == 1){
            ret = mbedtls_mpi_sub_mpi(a, a, p);
        } else{
            ret = mbedtls_mpi_add_mpi(a, a, p);
        }
    }
    else{
        ret = mbedtls_mpi_mod_mpi((mbedtls_mpi *)a, (const mbedtls_mpi *)base, (const mbedtls_mpi *)p);
    }
    return ret;
}

/* a = base**i (mod mod) */
int q_bn_mod_pow(qbn a, qbn base, int i, qbn mod) 
{
    int ret = 0;
    qbn exp = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(exp == NULL) return -1;
    mbedtls_mpi_init((mbedtls_mpi *)exp);
    ret = mbedtls_mpi_lset((mbedtls_mpi *)exp, (mbedtls_mpi_sint)i);
    if(ret == 0) {
        ret = mbedtls_mpi_exp_mod((mbedtls_mpi *)a, (const mbedtls_mpi *)base, (const mbedtls_mpi *)exp, (const mbedtls_mpi *)mod, NULL);
    }

    mbedtls_mpi_free((mbedtls_mpi *)exp);
    mbedtls_free(exp);
    return ret;
}

/* a = 1/b (mod p) */
int q_bn_mod_inverse(qbn a, qbn b, qbn p)
{
    int ret = 0;
    ret = mbedtls_mpi_inv_mod((mbedtls_mpi *)a, (const mbedtls_mpi *)b, (const mbedtls_mpi *)p);
    return ret;
}

/*a = op1 + op2*/
int q_bn_add(qbn a, qbn op1, qbn op2)
{
    int ret = 0;
    ret = mbedtls_mpi_add_mpi((mbedtls_mpi *)a, (const mbedtls_mpi *)op1, (const mbedtls_mpi *)op2);
    return ret;
}

/*a = op1 - op2*/
int q_bn_subtract(qbn a, qbn op1, qbn op2)
{
    int ret = 0;
    ret = mbedtls_mpi_sub_mpi((mbedtls_mpi *)a, (const mbedtls_mpi *)op1, (const mbedtls_mpi *)op2);
    return ret;
}

/*a = op1 * op2*/
int q_bn_multiply( qbn a, qbn op1, qbn op2)
{
    int ret = 0;
    ret = mbedtls_mpi_mul_mpi(( mbedtls_mpi *)a, (const mbedtls_mpi *)op1, (const mbedtls_mpi *)op2);
    return ret;
} 

/*a = (op1 * op2) mod p */
int q_bn_mul_mod(qbn a, qbn op1, qbn op2, qbn p)
{
    int ret = 0;
    qbn x = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(x == NULL) return -1;
    mbedtls_mpi_init((mbedtls_mpi *)x);
    ret = mbedtls_mpi_mul_mpi((mbedtls_mpi *)x, (const mbedtls_mpi *)op1, (const mbedtls_mpi *)op2);
    if (ret != 0) {
        goto cleanup;
    }
    ret = q_bn_mod(a, x, p);
    if (ret != 0) {
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free((mbedtls_mpi *)x);
    mbedtls_free(x);
    return ret;
}

/*n/d ==> n == q * d + r,  return (q, r)*/
int q_bn_div_qr(qbn q, qbn r, qbn n, qbn d)
{
    int ret = 0;
    ret = mbedtls_mpi_div_mpi((mbedtls_mpi *)q, (mbedtls_mpi *)r, (const mbedtls_mpi *)n, (const mbedtls_mpi *)d);  
    return ret;
}

/*left shift c bits*/
int q_bn_shift_left(qbn a, int c)
{
   return mbedtls_mpi_shift_l((mbedtls_mpi *)a, c);
}

/*right shit c bits, b = a / 2**c */
int q_bn_shift_right(qbn a, int c)
{
    return mbedtls_mpi_shift_r((mbedtls_mpi *)a, c);
}

int q_bn_comp(qbn a, qbn b)
{
    int ret = 0;
    ret =  mbedtls_mpi_cmp_abs((const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
    return ret;
}

int q_bn_comp_int(qbn a, int i)
{
    int ret = 0;
    ret = mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, (mbedtls_mpi_sint)i);
    return ret;
}

int q_bn_assign(qbn a, qbn b)
{
    int ret = 0;
    ret = mbedtls_mpi_copy((mbedtls_mpi *)a, (const mbedtls_mpi *)b);
    return ret;
}

int q_bn_clear(qbn x)
{
    mbedtls_mpi_free((mbedtls_mpi *)x);
    mbedtls_free(x);
    return 0;
}

size_t q_bn_num_bits(qbn op)
{
    return mbedtls_mpi_bitlen((const mbedtls_mpi *)op);
}

int q_bn_is_even(qbn a)
{
    int ret = 0;
    //Checking LSB 
    if((((mbedtls_mpi *)a)->private_p[0] == 0) || (((mbedtls_mpi *)a)->private_p[0] & 1) == 0){
        //mbedtls_printf("\tBig integer is EVEN.\n");
        ret = 1;
    }
    else{
        //mbedtls_printf("\tBig integer is ODD.\n");
        ret = 0;
    }
    return ret;
}

int q_bn_gcd(qbn rop, qbn op1, qbn op2)
{
    int ret = 0;
    ret = mbedtls_mpi_gcd( (mbedtls_mpi *)rop, (const mbedtls_mpi *)op1, (const mbedtls_mpi *)op2);
    return ret;
}

int q_bn_from_bytes(qbn rop, int count, int order, size_t size, int edian, int nails, void *ptr)
{
    int ret = 0;
    (void)order;
    (void)size;
    (void)edian;
    (void)nails;
    ret = mbedtls_mpi_read_binary_le((mbedtls_mpi *)rop, ptr, count);

    return ret;
}

int q_bn_to_bytes(unsigned char* ptr, qbn num, int index, int size)
{
    int ret = 0;
    ret = mbedtls_mpi_write_binary_le((mbedtls_mpi *)num, &ptr[index],(size_t)size);
    return ret;
}

/* a = (op1 * op2) mod p*/
int q_masq_bn_mul_mod(qbn a, qbn op1, qbn op2, qbn p)  {
    int ret = 0;
    qbn qtp_bn_helper_0;
    qtp_bn_helper_0 = q_bn_init_r();
    ret = q_bn_multiply(qtp_bn_helper_0, op1, op2);
    if (ret < 0)
        return ret;
    ret = q_bn_assign(a, qtp_bn_helper_0);
    if (ret < 0)
        return ret;
    q_bn_clear(qtp_bn_helper_0);
    ret = q_bn_mod(a, a, p);
    if (ret < 0)
        return ret;
    return ret;
}

/*
* generates random number which is not co-prime with p
* Return: SUCCESS(0) or ERROR(-1)
*/
int q_masq_bn_random_modp(qbn a, qbn p, int size, MASQ_rand_callback_t rand_cf, MASQ_RAND_handle rand_handle) {

    int32_t ret = 0;
    unsigned char *arr;
    arr = mbedtls_calloc(1, size);
    if(arr == NULL) return -1;

    memset(arr, 0, size);

    ret = rand_cf(rand_handle, size, arr);
    if(ret != 0)
    {
        mbedtls_printf("q_masq_bn_random_modp failed, returned %d\n", ret);
        mbedtls_free(arr);
        return -1;
    }
    else {
        q_bn_from_bytes(a, size, -1, sizeof(unsigned char), 0, 0, &arr[0]);
        q_bn_mod(a, a, p);
        mbedtls_free(arr);
    }

    return 0;
}

//generates random number
//Return: SUCCESS(0) or ERROR(-1)
int q_masq_bn_random(qbn a, MASQ_rand_callback_t rand_cf, MASQ_RAND_handle rand_handle) {
       
    unsigned char arr[2*MASQ_MPPK_BASE_SIZE_BYTES+1];

    memset(arr, 0, (2*MASQ_MPPK_BASE_SIZE_BYTES+1));

    if (rand_cf(rand_handle, (2*MASQ_MPPK_BASE_SIZE_BYTES+1), arr) != 0) {
        mbedtls_printf("q_masq_bn_random callback failed.\n");
        return (-1);
    }
    else {
        // Set LSB
        arr[0] |= 0x01;
        // Set MSB
        arr[2*MASQ_MPPK_BASE_SIZE_BYTES] |= 0x80;

        q_bn_from_bytes(a, (2*MASQ_MPPK_BASE_SIZE_BYTES+1), -1, sizeof(unsigned char), 0, 0, &arr[0]);
    }

    return 0;
}

// create qbn prime S
//Return: SUCCESS(0) or ERROR(-1)
int q_masq_ppk_gen_S(qbn S, MASQ_rand_callback_t rand_cf, MASQ_RAND_handle rand_handle) {
    int ret = -1;
    ret = q_masq_bn_random(S, rand_cf, rand_handle);
    return ret;
}


//generate R0 and Rn with gcd(R, S) = 1
//Return: SUCCESS(0) or ERROR(-1)
int q_masq_ppk_gen_R0_Rn(qbn R0, qbn Rn, qbn S, MASQ_rand_callback_t rand_cf, MASQ_RAND_handle rand_handle) {

    qbn helper_2;
    q_bn_init(helper_2);

    int success = 0;
    for (int i = 0; i < RUN_RANDOM_LOOP; i++) {
        if (q_masq_bn_random_modp(R0, S, 2*MASQ_MPPK_BASE_SIZE_BYTES, rand_cf, rand_handle) == 0) {
            q_bn_gcd(helper_2, S, R0);
            if (q_bn_comp_int(helper_2, 1) == 0) {
                success = 1;
                break;
            }
        }
    }
    if (!success) {
        mbedtls_printf("q_masq_ppk_gen_R0_Rn random failed.\n");
        q_bn_clear(helper_2);
        return -1;
    }

    success = 0;
    for (int i = 0; i < RUN_RANDOM_LOOP; i++) {
        if (q_masq_bn_random_modp(Rn, S, (2*MASQ_MPPK_BASE_SIZE_BYTES+1)-1, rand_cf, rand_handle) == 0) {
            q_bn_gcd(helper_2, S, Rn);
            if (q_bn_comp_int(helper_2, 1) == 0) {
                success = 1;
                break;
            }
        }
    }
    if (!success) {
        mbedtls_printf("q_masq_ppk_gen_R0_Rn random failed.\n");
        q_bn_clear(helper_2);
        return -1;
    }

    q_bn_clear(helper_2);

    return 0;
}

int q_masq_ppk_gen_session_key(uint8_t *ss, int ss_size, MASQ_rand_callback_t rand_cf, MASQ_RAND_handle rand_handle)
{
    if(ss == NULL || ss_size <= 0)
        return -1;

    if(rand_cf(rand_handle, ss_size, ss) == 0)
    {
        return 0;
    }
    else {
        mbedtls_printf("q_masq_ppk_gen_session_key Random Generator failed.\n");
        return -1;
    }
}

int q_masq_ppk_calc_k(qbn a, qbn b, qbn p, qbn K) {

    int ret = 0;
    qbn helper_0;
    q_bn_init(helper_0);
    ret = q_bn_mod_inverse(helper_0, a, p);
    if (ret < 0) return ret;
    ret = q_masq_bn_mul_mod(K, b, helper_0, p);
    if (ret < 0) return ret;
    q_bn_clear(helper_0);
    return ret;
}

int q_masq_ppk_calc_linear_session_key(qbn K, qbn h0, qbn p, qbn f0, qbn hL, qbn fL, qbn session_key) {

    int ret = 0;
    qbn helper_0;
    q_bn_init(helper_0);
    ret = q_masq_bn_mul_mod(helper_0, K, h0, p);
    if (ret < 0) return ret;
    ret = q_bn_subtract(helper_0, helper_0, f0);
    if (ret < 0) return ret;
    ret = q_bn_mod(session_key, helper_0, p);
    if (ret < 0) return ret;
    ret = q_masq_bn_mul_mod(helper_0, K, hL, p);
    if (ret < 0) return ret;
    ret = q_bn_subtract(helper_0, fL, helper_0);
    if (ret < 0) return ret;
    ret = q_bn_mod(helper_0, helper_0, p);
    if (ret < 0) return ret;
    ret = q_bn_mod_inverse(helper_0, helper_0, p);
    if (ret < 0) return ret;
    ret = q_masq_bn_mul_mod(session_key, session_key, helper_0, p);
    if (ret < 0) return ret;
    q_bn_clear(helper_0);
    return ret;
}

uint32_t q_masq_ppk_crc32(uint8_t *message, int32_t len) {

    int i, j;
    uint32_t byte, crc, mask;

    crc = 0xFFFFFFFF;
    for (i = 0; i < len; i++) {
        byte = message[i]; 
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

int q_bn_SHA256(unsigned char *output, const unsigned char *input, unsigned int len) {
    mbedtls_sha256(input, len, output, 0); //0 for SHA-256, or 1 for SHA-224
    return 0;
}

int q_bn_SHA512(unsigned char *output, const unsigned char *input, unsigned int len){
    mbedtls_sha512(input, len, output, 0); //0 for SHA-512, or 1 for SHA-384.
    return 0;
}

int q_bn_SHA384(unsigned char *output, const unsigned char *input, unsigned int len){
    mbedtls_sha512(input, len, output, 1); //0 for SHA-512, or 1 for SHA-384.
    return 0;
}

//below functions not used much
int q_bn_set_neg(qbn a) {
    ((mbedtls_mpi *)a)->private_s = -1;
    if(((mbedtls_mpi *)a)->private_s == -1){
        return 0;
    } else {
        return -1;
    }
}

int q_bn_is_neg(qbn a) {
    if(((mbedtls_mpi *)a)->private_s == -1){
        return 0;
    } else {
        return -1;
    }
}

/*a = (b + c) mod p*/
int q_bn_mod_add(qbn a, qbn b, qbn c, qbn d)
{
    int ret = 0;
    ret = mbedtls_mpi_add_mpi((mbedtls_mpi *)a, (const mbedtls_mpi *)b, (const mbedtls_mpi *)c);
    ret = q_bn_mod(a,a,d);
    return ret;
}

int q_bn_set_int(qbn a, int b)
{
    return mbedtls_mpi_lset((mbedtls_mpi *)a, (mbedtls_mpi_sint)b);
}

// int q_bn_and(qbn a, qbn b, qbn c)
// {
//     // TODO
//     return -1;
// }

int q_bn_mod_pow_qbn(qbn a, qbn base, qbn i, qbn mod)
{
    int ret = 0;
    ret = mbedtls_mpi_exp_mod((mbedtls_mpi *)a, (const mbedtls_mpi *)base, (const mbedtls_mpi *)i, (const mbedtls_mpi *)mod, NULL);
    return ret;
}

/* d = (a - b) mod p*/
int q_bn_mod_sub(qbn d, qbn a, qbn b, qbn p)
{
    int ret = 0;
    ret = mbedtls_mpi_sub_mpi((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
    ret = q_bn_mod(d,d,p);
    return ret;
}

/*a = b - c*/
int q_bn_subtract_int(qbn a, qbn b, int c)
{
    int ret = 0;
    ret = mbedtls_mpi_sub_int((mbedtls_mpi *)a, (const mbedtls_mpi *)b, (mbedtls_mpi_sint)c);
    return ret;
}

/*a = b/c =>  b = c * a + d */
int q_bn_divide_int(qbn a, qbn b, int c)
{
    int ret = 0;
    qbn d = mbedtls_calloc(1, sizeof(mbedtls_mpi));
    if(d == NULL) return -1;
    mbedtls_mpi_init((mbedtls_mpi *)d);
    ret = mbedtls_mpi_div_int((mbedtls_mpi *)a, (mbedtls_mpi *)d, (mbedtls_mpi *)b, (mbedtls_mpi_sint)c);
    mbedtls_mpi_free((mbedtls_mpi *)d);
    mbedtls_free(d);
    return ret;
}


// ONLY USED FOR TEST PURPOSE
int q_bn_printf(char *text, qbn value) {
    mbedtls_printf("%s:", text);
    mbedtls_mpi_write_file(NULL, (mbedtls_mpi *) value, 16, NULL);
    return 0;
}

#endif