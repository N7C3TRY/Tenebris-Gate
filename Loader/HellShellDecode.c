#include "HellShellDecode.h"
#include <string.h>

static int ParseOctet(const char** pp) {
    int val = 0;
    while (**pp >= '0' && **pp <= '9') {
        val = val * 10 + (**pp - '0');
        (*pp)++;
    }
    return val;
}

BOOL HellShellDecodeIpv4(
    const char* szIpv4Array[],
    DWORD       dwCount,
    BYTE*       pOutputKey,
    BYTE*       pOutputIv
) {
    if (dwCount != HELLSHELL_IPV4_COUNT)
        return FALSE;

    BYTE raw[48];

    for (DWORD i = 0; i < dwCount; i++) {
        const char* p = szIpv4Array[i];
        int offset = i * 4;

        raw[offset]     = (BYTE)ParseOctet(&p); if (*p == '.') p++;
        raw[offset + 1] = (BYTE)ParseOctet(&p); if (*p == '.') p++;
        raw[offset + 2] = (BYTE)ParseOctet(&p); if (*p == '.') p++;
        raw[offset + 3] = (BYTE)ParseOctet(&p);
    }

    memcpy(pOutputKey, raw, 32);
    memcpy(pOutputIv, raw + 32, 16);

    SecureZeroMemory(raw, sizeof(raw));
    return TRUE;
}
