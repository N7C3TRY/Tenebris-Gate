#ifndef COMPRESS_H
#define COMPRESS_H

#include <windows.h>

#ifndef COMPRESSION_FORMAT_LZNT1
#define COMPRESSION_FORMAT_LZNT1 0x0002
#endif
#ifndef COMPRESSION_ENGINE_MAXIMUM
#define COMPRESSION_ENGINE_MAXIMUM 0x0100
#endif

BOOL CompressBuffer(
    const BYTE* pInput,
    DWORD       dwInputSize,
    BYTE**      ppOutput,
    DWORD*      pdwOutputSize
);

#endif /* COMPRESS_H */
