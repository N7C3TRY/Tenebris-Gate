#ifndef LOADER_AESCRYPT_H
#define LOADER_AESCRYPT_H

#include <windows.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE  16
#define AES_BLOCK    16

BOOL AesDecryptPayload(
    const BYTE* pKey,
    const BYTE* pIv,
    const BYTE* pCiphertext,
    DWORD       dwCiphertextSize,
    BYTE**      ppPlaintext,
    DWORD*      pdwPlaintextSize
);

#endif /* LOADER_AESCRYPT_H */
