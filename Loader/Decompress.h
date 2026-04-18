#ifndef DECOMPRESS_H
#define DECOMPRESS_H

#include <windows.h>

BOOL DecompressPayload(
    const BYTE* pCompressed,
    DWORD       dwCompressedSize,
    DWORD       dwOriginalSize,
    BYTE**      ppDecompressed,
    DWORD*      pdwDecompressedSize
);

#endif /* DECOMPRESS_H */
