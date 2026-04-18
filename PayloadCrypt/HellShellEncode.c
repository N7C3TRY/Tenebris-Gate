#include "HellShellEncode.h"
#include <stdio.h>

BOOL HellShellEncodeToIpv4(
    const BYTE* pKeyIv,
    DWORD       dwSize,
    char        szIpv4Array[HELLSHELL_IPV4_COUNT][16]
) {
    if (dwSize != HELLSHELL_KEY_IV_SIZE)
        return FALSE;

    for (int i = 0; i < HELLSHELL_IPV4_COUNT; i++) {
        int offset = i * 4;
        sprintf_s(szIpv4Array[i], 16, "%d.%d.%d.%d",
            pKeyIv[offset], pKeyIv[offset + 1],
            pKeyIv[offset + 2], pKeyIv[offset + 3]);
    }
    return TRUE;
}

void HellShellWriteHeader(
    FILE* fp,
    const char szIpv4Array[HELLSHELL_IPV4_COUNT][16]
) {
    fprintf(fp, "#ifndef PAYLOAD_KEY_H\n");
    fprintf(fp, "#define PAYLOAD_KEY_H\n\n");
    fprintf(fp, "/*\n");
    fprintf(fp, " * AES-256 Key + IV encoded as IPv4 addresses (HellShell IPFuscation)\n");
    fprintf(fp, " * 12 addresses x 4 bytes = 48 bytes (32 key + 16 IV)\n");
    fprintf(fp, " */\n\n");
    fprintf(fp, "static const char* g_Ipv4KeyIv[%d] = {\n", HELLSHELL_IPV4_COUNT);
    for (int i = 0; i < HELLSHELL_IPV4_COUNT; i++) {
        fprintf(fp, "    \"%s\"%s\n",
            szIpv4Array[i],
            (i < HELLSHELL_IPV4_COUNT - 1) ? "," : "");
    }
    fprintf(fp, "};\n\n");
    fprintf(fp, "#endif /* PAYLOAD_KEY_H */\n");
}
