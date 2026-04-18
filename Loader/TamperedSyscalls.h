#ifndef TAMPERED_SYSCALLS_H
#define TAMPERED_SYSCALLS_H

#include <windows.h>
#include "Structs.h"

#define MAX_SYSCALL_ENTRIES 512

#define HASH_NtAllocateVirtualMemory    0x6793C34C
#define HASH_NtProtectVirtualMemory     0x082962C8
#define HASH_NtCreateThreadEx           0xCB0C2130
#define HASH_NtWaitForSingleObject      0x4C6DC63C
#define HASH_NtFreeVirtualMemory        0x471AA7E9
#define HASH_NtQuerySecurityObject      0x0FE62D8C

BOOL InitTamperedSyscalls(void);
void CleanupTamperedSyscalls(void);

DWORD GetSSN(DWORD dwFunctionHash);

NTSTATUS TamperedNtAllocateVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
);

NTSTATUS TamperedNtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

NTSTATUS TamperedNtCreateThreadEx(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       StartRoutine,
    PVOID       Argument,
    ULONG       CreateFlags,
    SIZE_T      ZeroBits,
    SIZE_T      StackSize,
    SIZE_T      MaximumStackSize,
    PVOID       AttributeList
);

NTSTATUS TamperedNtWaitForSingleObject(
    HANDLE         Handle,
    BOOLEAN        Alertable,
    PLARGE_INTEGER Timeout
);

NTSTATUS TamperedNtFreeVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

#endif /* TAMPERED_SYSCALLS_H */
