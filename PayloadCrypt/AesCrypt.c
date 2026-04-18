#include "AesCrypt.h"
#include "ctaes.h"
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

BOOL GenerateKeyIv(BYTE pKey[AES_KEY_SIZE], BYTE pIv[AES_IV_SIZE]) {
    NTSTATUS s1 = BCryptGenRandom(NULL, pKey, AES_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    NTSTATUS s2 = BCryptGenRandom(NULL, pIv, AES_IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (s1 == 0 && s2 == 0);
}

BOOL AesEncryptPayload(
    const BYTE* pKey,
    const BYTE* pIv,
    const BYTE* pPlaintext,
    DWORD       dwPlaintextSize,
    BYTE**      ppCiphertext,
    DWORD*      pdwCiphertextSize
) {
    BYTE  bPadLen  = (BYTE)(AES_BLOCK - (dwPlaintextSize % AES_BLOCK));
    DWORD dwPadded = dwPlaintextSize + bPadLen;

    BYTE* pPadded = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPadded);
    if (!pPadded) return FALSE;

    memcpy(pPadded, pPlaintext, dwPlaintextSize);
    for (DWORD i = dwPlaintextSize; i < dwPadded; i++)
        pPadded[i] = bPadLen;

    BYTE* pOutput = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPadded);
    if (!pOutput) {
        HeapFree(GetProcessHeap(), 0, pPadded);
        return FALSE;
    }

    AES256_CBC_ctx ctx;
    AES256_CBC_init(&ctx, pKey, pIv);
    AES256_CBC_encrypt(&ctx, dwPadded / AES_BLOCK, pOutput, pPadded);

    SecureZeroMemory(&ctx, sizeof(ctx));
    HeapFree(GetProcessHeap(), 0, pPadded);

    *ppCiphertext     = pOutput;
    *pdwCiphertextSize = dwPadded;

    printf("[+] AES-256-CBC encrypted %lu -> %lu bytes (PKCS7 padded)\n",
           (unsigned long)dwPlaintextSize, (unsigned long)dwPadded);
    return TRUE;
}
