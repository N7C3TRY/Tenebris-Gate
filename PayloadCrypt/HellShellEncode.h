#ifndef HELLSHELL_ENCODE_H
#define HELLSHELL_ENCODE_H

#include <windows.h>
#include <stdio.h>

#define HELLSHELL_KEY_IV_SIZE  48  /* 32-byte key + 16-byte IV */
#define HELLSHELL_IPV4_COUNT   12 /* 48 / 4 = 12 IPv4 addresses */

BOOL HellShellEncodeToIpv4(
    const BYTE* pKeyIv,
    DWORD       dwSize,
    char        szIpv4Array[HELLSHELL_IPV4_COUNT][16]
);

void HellShellWriteHeader(
    FILE* fp,
    const char szIpv4Array[HELLSHELL_IPV4_COUNT][16]
);

#endif /* HELLSHELL_ENCODE_H */
