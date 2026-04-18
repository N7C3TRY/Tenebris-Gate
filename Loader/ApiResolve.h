#ifndef API_RESOLVE_H
#define API_RESOLVE_H

#include <windows.h>

#define HASH_NTDLL              0x22D3B5ED
#define HASH_KERNEL32           0x7040EE75

DWORD Djb2HashA(const char* str);
DWORD Djb2HashW(const WCHAR* str);

HMODULE GetModuleByHash(DWORD dwHash);
FARPROC GetProcByHash(HMODULE hModule, DWORD dwHash);

#endif /* API_RESOLVE_H */
