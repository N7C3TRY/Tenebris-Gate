#include "AesCrypt.h"
#include "ctaes.h"
#include <string.h>

BOOL AesDecryptPayload(
    const BYTE* pKey,
    const BYTE* pIv,
    const BYTE* pCiphertext,
    DWORD       dwCiphertextSize,
    BYTE**      ppPlaintext,
    DWORD*      pdwPlaintextSize
) {
    if (dwCiphertextSize == 0 || dwCiphertextSize % AES_BLOCK != 0)
        return FALSE;

    BYTE* pOutput = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCiphertextSize);
    if (!pOutput) return FALSE;

    AES256_CBC_ctx ctx;
    AES256_CBC_init(&ctx, pKey, pIv);
    AES256_CBC_decrypt(&ctx, dwCiphertextSize / AES_BLOCK, pOutput, pCiphertext);
    SecureZeroMemory(&ctx, sizeof(ctx));

    BYTE bPadLen = pOutput[dwCiphertextSize - 1];
    if (bPadLen == 0 || bPadLen > AES_BLOCK) {
        HeapFree(GetProcessHeap(), 0, pOutput);
        return FALSE;
    }

    for (DWORD i = 0; i < bPadLen; i++) {
        if (pOutput[dwCiphertextSize - 1 - i] != bPadLen) {
            HeapFree(GetProcessHeap(), 0, pOutput);
            return FALSE;
        }
    }

    *ppPlaintext     = pOutput;
    *pdwPlaintextSize = dwCiphertextSize - bPadLen;
    return TRUE;
}
