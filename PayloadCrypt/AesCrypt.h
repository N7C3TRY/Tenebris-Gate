#ifndef AESCRYPT_H
#define AESCRYPT_H

#include <windows.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE  16
#define AES_BLOCK    16

BOOL GenerateKeyIv(BYTE pKey[AES_KEY_SIZE], BYTE pIv[AES_IV_SIZE]);

BOOL AesEncryptPayload(
    const BYTE* pKey,
    const BYTE* pIv,
    const BYTE* pPlaintext,
    DWORD       dwPlaintextSize,
    BYTE**      ppCiphertext,
    DWORD*      pdwCiphertextSize
);

#endif /* AESCRYPT_H */
