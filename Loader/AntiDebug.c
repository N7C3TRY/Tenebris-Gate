#include "AntiDebug.h"
#include "Structs.h"
#include "ApiResolve.h"
#include "Config.h"
#include <intrin.h>
#include <tlhelp32.h>

BOOL IsDebuggerPresentPeb(void) {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged;
}

BOOL IsRemoteDebuggerAttached(void) {
    HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
    if (!hNtdll) return FALSE;

    #define HASH_NtQueryInformationProcess 0xD034FC62

    fnNtQueryInformationProcess pNtQIP = (fnNtQueryInformationProcess)
        GetProcByHash(hNtdll, HASH_NtQueryInformationProcess);
    if (!pNtQIP) return FALSE;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG ulRetLen = 0;
    NTSTATUS status = pNtQIP((HANDLE)-1, ProcessBasicInformation, &pbi, sizeof(pbi), &ulRetLen);
    if (!NT_SUCCESS(status)) return FALSE;

    PPEB pPeb = pbi.PebBaseAddress;
    return pPeb ? pPeb->BeingDebugged : FALSE;
}

BOOL IsHardwareBreakpointSet(void) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return FALSE;

    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

BOOL CanOpenCsrss(void) {
    HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
    if (!hNtdll) return FALSE;

    #define HASH_NtOpenProcess 0x5003C058

    fnNtOpenProcess pNtOpenProcess = (fnNtOpenProcess)
        GetProcByHash(hNtdll, HASH_NtOpenProcess);
    if (!pNtOpenProcess) return FALSE;

    DWORD dwCsrssPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"csrss.exe") == 0) {
                dwCsrssPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!dwCsrssPid) return FALSE;

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0 };
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwCsrssPid, NULL };
    NTSTATUS status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (NT_SUCCESS(status) && hProcess) {
        CloseHandle(hProcess);
        return TRUE;
    }
    return FALSE;
}

static BOOL IsPrime(unsigned long long n) {
    if (n < 2) return FALSE;
    if (n < 4) return TRUE;
    if (n % 2 == 0 || n % 3 == 0) return FALSE;
    for (unsigned long long i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0) return FALSE;
    return TRUE;
}

void SandboxDelayPrimeCounting(DWORD dwSeconds) {
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    volatile unsigned long long count = 0;
    unsigned long long candidate = 2;

    do {
        if (IsPrime(candidate)) count++;
        candidate++;
        QueryPerformanceCounter(&now);
    } while ((double)(now.QuadPart - start.QuadPart) / freq.QuadPart < (double)dwSeconds);
}

BOOL RunAntiDebugChecks(void) {
#if ENABLE_ANTI_DEBUG
    DBG_STEP("  Check 1/4: PEB.BeingDebugged...");
    if (IsDebuggerPresentPeb()) {
        DBG_FAIL("  DETECTED: PEB.BeingDebugged is TRUE");
        return FALSE;
    }
    DBG_OK("  PEB.BeingDebugged = FALSE (clean)");

    DBG_STEP("  Check 2/4: Remote debugger via NtQueryInformationProcess...");
    if (IsRemoteDebuggerAttached()) {
        DBG_FAIL("  DETECTED: Remote debugger attached");
        return FALSE;
    }
    DBG_OK("  No remote debugger (clean)");

    DBG_STEP("  Check 3/4: Hardware breakpoints (DR0-DR3)...");
    if (IsHardwareBreakpointSet()) {
        DBG_FAIL("  DETECTED: Hardware breakpoints already set");
        return FALSE;
    }
    DBG_OK("  No hardware breakpoints (clean)");

    DBG_STEP("  Check 4/4: csrss.exe open test...");
    if (CanOpenCsrss()) {
        DBG_FAIL("  DETECTED: Can open csrss.exe with PROCESS_ALL_ACCESS (debug privilege active)");
        return FALSE;
    }
    DBG_OK("  Cannot open csrss.exe (clean -- no debug privilege)");
#endif

#if ENABLE_SANDBOX_DELAY
    DBG_STEP("  Sandbox delay: counting primes for %d seconds...", SANDBOX_DELAY_SECONDS);
    SandboxDelayPrimeCounting(SANDBOX_DELAY_SECONDS);
    DBG_OK("  Sandbox delay complete");
#endif

    return TRUE;
}
