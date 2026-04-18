#include "ApiResolve.h"
#include "Structs.h"
#include <intrin.h>

DWORD Djb2HashA(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

DWORD Djb2HashW(const WCHAR* str) {
    DWORD hash = 5381;
    WCHAR c;
    while ((c = *str++)) {
        if (c >= L'A' && c <= L'Z')
            c += 0x20;
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}

HMODULE GetModuleByHash(DWORD dwHash) {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA          pLdr  = pPeb->Ldr;
    PLIST_ENTRY            pHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY            pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = (PLDR_DATA_TABLE_ENTRY)pEntry;

        if (pMod->BaseDllName.Buffer) {
            DWORD h = Djb2HashW(pMod->BaseDllName.Buffer);
            if (h == dwHash)
                return (HMODULE)pMod->DllBase;
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}

FARPROC GetProcByHash(HMODULE hModule, DWORD dwHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);

    DWORD dwExportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + dwExportRva);

    DWORD* pNames    = (DWORD*)((BYTE*)hModule + pExport->AddressOfNames);
    WORD*  pOrdinals = (WORD*)((BYTE*)hModule + pExport->AddressOfNameOrdinals);
    DWORD* pFuncs    = (DWORD*)((BYTE*)hModule + pExport->AddressOfFunctions);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* szName = (const char*)((BYTE*)hModule + pNames[i]);
        if (Djb2HashA(szName) == dwHash)
            return (FARPROC)((BYTE*)hModule + pFuncs[pOrdinals[i]]);
    }
    return NULL;
}
