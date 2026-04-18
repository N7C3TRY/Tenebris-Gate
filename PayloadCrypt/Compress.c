#include "Compress.h"
#include <stdio.h>

typedef NTSTATUS(NTAPI* fnRtlCompressBuffer)(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    ULONG  UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID  WorkSpace
);

typedef NTSTATUS(NTAPI* fnRtlGetCompressionWorkSpaceSize)(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize
);

BOOL CompressBuffer(
    const BYTE* pInput,
    DWORD       dwInputSize,
    BYTE**      ppOutput,
    DWORD*      pdwOutputSize
) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    fnRtlCompressBuffer           pRtlCompressBuffer           = (fnRtlCompressBuffer)GetProcAddress(hNtdll, "RtlCompressBuffer");
    fnRtlGetCompressionWorkSpaceSize pRtlGetCompressionWorkSpaceSize = (fnRtlGetCompressionWorkSpaceSize)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");

    if (!pRtlCompressBuffer || !pRtlGetCompressionWorkSpaceSize)
        return FALSE;

    USHORT usFormat = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;
    ULONG  ulWorkSpaceSize = 0, ulFragmentSize = 0;

    NTSTATUS status = pRtlGetCompressionWorkSpaceSize(usFormat, &ulWorkSpaceSize, &ulFragmentSize);
    if (status != 0) {
        printf("[!] RtlGetCompressionWorkSpaceSize failed: 0x%08X\n", (unsigned int)status);
        return FALSE;
    }

    PVOID pWorkSpace = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulWorkSpaceSize);
    if (!pWorkSpace) return FALSE;

    ULONG ulCompressedSize = dwInputSize + 0x1000;
    BYTE* pCompressed = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulCompressedSize);
    if (!pCompressed) {
        HeapFree(GetProcessHeap(), 0, pWorkSpace);
        return FALSE;
    }

    ULONG ulFinalSize = 0;
    status = pRtlCompressBuffer(
        usFormat,
        (PUCHAR)pInput,
        dwInputSize,
        pCompressed,
        ulCompressedSize,
        4096,
        &ulFinalSize,
        pWorkSpace
    );

    HeapFree(GetProcessHeap(), 0, pWorkSpace);

    if (status != 0) {
        printf("[!] RtlCompressBuffer failed: 0x%08X\n", (unsigned int)status);
        HeapFree(GetProcessHeap(), 0, pCompressed);
        return FALSE;
    }

    *ppOutput      = pCompressed;
    *pdwOutputSize = ulFinalSize;
    return TRUE;
}
