#ifndef STRUCTS_H
#define STRUCTS_H

#include <windows.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN                      InheritedAddressSpace;
    BOOLEAN                      ReadImageFileExecOptions;
    BOOLEAN                      BeingDebugged;
    BOOLEAN                      SpareBool;
    HANDLE                       Mutant;
    PVOID                        ImageBaseAddress;
    PPEB_LDR_DATA                Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T   ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PPEB      PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    HANDLE    UniqueProcessId;
    HANDLE    InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _SYSCALL_ENTRY {
    DWORD   dwHash;
    DWORD   dwSSN;
    PVOID   pAddress;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _TAMPERED_SYSCALL_ARGS {
    DWORD       dwSSN;
    ULONG_PTR   Arg1;
    ULONG_PTR   Arg2;
    ULONG_PTR   Arg3;
    ULONG_PTR   Arg4;
} TAMPERED_SYSCALL_ARGS, * PTAMPERED_SYSCALL_ARGS;

typedef NTSTATUS(NTAPI* fnRtlDecompressBuffer)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS(NTAPI* fnNtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef PVOID(NTAPI* fnRtlAddVectoredExceptionHandler)(
    ULONG                       First,
    PVECTORED_EXCEPTION_HANDLER Handler
);

typedef ULONG(NTAPI* fnRtlRemoveVectoredExceptionHandler)(
    PVOID Handle
);

#endif /* STRUCTS_H */
