# Tenebris-Gate
multi layer encryption for payloads with options of delivery welcome to the Tenebris side


<img width="1360" height="840" alt="tenebris_gate_logo" src="https://github.com/user-attachments/assets/bf6942b9-c0a6-454e-a10b-46e21a9e4c05" />




# SilentForge -- Stacked Silent Execution Pipeline

Multi-layered evasion framework for CES lab exercises. Takes raw shellcode (`thinkpad.bin`) through a 10-layer obfuscation and execution pipeline.

## Evasion Stack

| Layer | Technique | What It Defeats |
|-------|-----------|-----------------|
| 1 | LZNT1 Compression | Signature pattern matching |
| 2 | AES-256-CBC Encryption | All static analysis |
| 3 | HellShell IPv4 Key Encoding | Key extraction from binary |
| 4 | Anti-Debug Gate | Debuggers, analyst tools |
| 5 | Sandbox Delay (prime counting) | Automated sandbox analysis |
| 6 | PEB Masquerade (explorer.exe) | Process name/path inspection |
| 7 | Djb2 API Hashing | Import table analysis |
| 8 | Tampered Syscalls (HW breakpoints) | Userland EDR hooks |
| 9 | RW->RX Memory (no RWX) | RWX memory alerts |
| 10 | Secure Memory Zeroing | Post-execution memory forensics |

## Prerequisites

- Visual Studio 2022+ with **Desktop development with C++** workload
- Windows SDK 10.0+

## Quick Start (3 commands)

```batch
:: 1. Build everything
msbuild SilentForge.sln /p:Configuration=Release /p:Platform=x64

:: 2. Encrypt your payload (generates headers + binary resource)
Build\Release\PayloadCrypt.exe ..\thinkpad.bin Loader\

:: 3. Rebuild Loader to embed the encrypted payload
msbuild SilentForge.sln /p:Configuration=Release /p:Platform=x64 /t:Loader
```

Output: `Build\Release\Loader.exe` -- no console window, all layers active.

## How It Works

### Build-Time (PayloadCrypt.exe)

1. Reads raw shellcode from disk
2. LZNT1 compresses (breaks byte-level signatures)
3. AES-256-CBC encrypts with random key/IV (eliminates static analysis)
4. Saves encrypted blob as `encrypted_payload.bin` (embedded in Loader via .rc resource)
5. Encodes 48-byte key+IV as 12 IPv4 addresses (HellShell IPFuscation)
6. Outputs `PayloadKey.h` (IPv4 key array) and `PayloadInfo.h` (size metadata)

### Runtime (Loader.exe)

1. **Anti-debug checks** block debuggers (PEB, remote debug, HW breakpoints, csrss open test)
2. **Prime counting** burns CPU time to outlast sandbox timeouts
3. **PEB masquerade** overwrites process parameters to appear as `explorer.exe`
4. **Tampered syscalls engine** starts: finds all Nt* SSNs by sorting Zw* stubs, sets HW breakpoint on decoy `NtQuerySecurityObject` stub, registers VEH
5. **IPv4 key decoded** back to raw 32-byte AES key + 16-byte IV
6. **Encrypted payload extracted** from PE resource section
7. **AES-256-CBC decrypts** the payload (constant-time ctaes)
8. **LZNT1 decompresses** to recover original shellcode
9. **RW memory allocated** via tampered `NtAllocateVirtualMemory` (EDR sees `NtQuerySecurityObject` with NULL args)
10. Shellcode copied, then **flipped to RX** via tampered `NtProtectVirtualMemory` (no RWX ever)
11. **Thread created** via tampered `NtCreateThreadEx`
12. All plaintext **securely zeroed** from heap

## Configuration

Toggle individual layers in `Loader\Config.h`:

```c
#define ENABLE_ANTI_DEBUG           1
#define ENABLE_SANDBOX_DELAY        1
#define ENABLE_PEB_MASQUERADE       1
#define ENABLE_AES_ENCRYPTION       1
#define ENABLE_HELLSHELL_KEY        1
#define ENABLE_LZNT1_COMPRESS       1
#define ENABLE_TAMPERED_SYSCALLS    1
#define SANDBOX_DELAY_SECONDS       8
```

## Project Structure

```
SilentForge/
├── SilentForge.sln
├── PayloadCrypt/               # Build-time tool
│   ├── Main.c                  # Orchestration
│   ├── Compress.c/h            # LZNT1 via RtlCompressBuffer
│   ├── AesCrypt.c/h            # AES-256-CBC encrypt (BCryptGenRandom + ctaes)
│   ├── HellShellEncode.c/h     # Key bytes -> IPv4 array
│   └── ctaes/                  # Constant-time AES (vendored)
├── Loader/                     # Runtime loader (/SUBSYSTEM:WINDOWS)
│   ├── Main.c                  # WinMain -- full pipeline orchestration
│   ├── Config.h                # Feature toggles
│   ├── Structs.h               # NT typedefs and structures
│   ├── Resource.h/.rc          # Embeds encrypted_payload.bin
│   ├── ApiResolve.c/h          # Djb2 hash-based PEB module/export walking
│   ├── AntiDebug.c/h           # 4 anti-debug checks + sandbox delay
│   ├── PebMasquerade.c/h       # Spoof PEB as explorer.exe
│   ├── TamperedSyscalls.c/h    # HW-BP syscall tampering engine
│   ├── AesCrypt.c/h            # AES-256-CBC decrypt
│   ├── HellShellDecode.c/h     # IPv4 array -> raw key bytes
│   ├── Decompress.c/h          # LZNT1 via RtlDecompressBuffer
│   ├── PayloadInfo.h           # [generated] Size metadata
│   ├── PayloadKey.h            # [generated] IPv4-encoded AES key+IV
│   ├── encrypted_payload.bin   # [generated] AES-encrypted compressed shellcode
│   └── ctaes/                  # Constant-time AES (vendored)
└── README.md
```

## References

- [HellShell](https://github.com/NUL0x4C/HellShell) -- IPFuscation (IPv4/IPv6/MAC encoding)
- [GhostlyHollowingViaTamperedSyscalls2](https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls2) -- Tampered syscalls via HW breakpoints
- [VX-API](https://github.com/NUL0x4C/VX-API) -- Anti-debug, PEB masquerade, API hashing
- [ctaes](https://github.com/NUL0x4C/ctaes) -- Constant-time AES implementation
- [MaldevAcademyLdr.2](https://github.com/NUL0x4C/MaldevAcademyLdr.2) -- Architecture reference
