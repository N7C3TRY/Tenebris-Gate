#ifndef HELLSHELL_DECODE_H
#define HELLSHELL_DECODE_H

#include <windows.h>

#define HELLSHELL_IPV4_COUNT 12

BOOL HellShellDecodeIpv4(
    const char* szIpv4Array[],
    DWORD       dwCount,
    BYTE*       pOutputKey,
    BYTE*       pOutputIv
);

#endif /* HELLSHELL_DECODE_H */
