/*********************************************************************
 * Copyright (c) 2016 Pieter Wuille                                  *
 * Distributed under the MIT software license, see the accompanying  *
 * file COPYING or https://opensource.org/licenses/mit-license.php.  *
 *********************************************************************/

#ifndef CTAES_H
#define CTAES_H

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[11];
} AES128_ctx;

typedef struct {
    AES_state rk[13];
} AES192_ctx;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;

void AES256_init(AES256_ctx* ctx, const unsigned char* key32);
void AES256_encrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES256_decrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

void AES256_CBC_init(AES256_CBC_ctx* ctx, const unsigned char* key32, const uint8_t* iv);
void AES256_CBC_encrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain);
void AES256_CBC_decrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char* encrypted);

#endif /* CTAES_H */
