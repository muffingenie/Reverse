# CTI Report: Novel Garble-Obfuscated Go RAT/Stager
**Sample**: `sample.exe`  
**Date**: 2026-05-03  
**Analyst**: REMnux MCP Analysis  
**Severity**: CRITICAL  
**Classification**: Novel Go-based Remote Access Implant / Stager (unclassified family)

---

## Executive Summary

`sample.exe` is a highly sophisticated **garble-obfuscated Go implant** (PE32, Windows x86) compiled with Go 1.25.9. It implements a full process injection framework with PPID spoofing, a multi-layer encryption stack (ChaCha20/Salsa20 + AES-NI + RC4 + MurmurHash3 + QuickLZ), and encrypted C2 communications (no plaintext C2 recoverable statically). Zero known YARA family signatures — this is a novel or custom-built tool. The build discipline (zeroed timestamp, `-trimpath=true`, garble, fake certificate) indicates an operator with strong OPSEC awareness.

---

## File Metadata

| Field | Value |
|-------|-------|
| Filename | `sample.exe` |
| Size | 2,940,416 bytes (2.94 MB) |
| MD5 | `51fe8e4c8974c3a1098784da1b195f1d` |
| SHA1 | `023ff6ba089f30ec1e1f3fc471478baabebc5be2` |
| SHA256 | `f061a7c86a39411cd19ba983a15953c37df9ce31e6b01babc264421a5658780c` |
| ssdeep | `49152:RGPGTIlZrHmlSdyGUDRKygzkjiNwLz2IL3zbslT1RROzmJ3pxab4JqaHpbn47qKA:o4IlZjmlmyGUDRKyg4kMnslTvQzmJ3pt` |
| Type | PE32 executable (GUI) Intel 80386, Windows |
| Sections | 7 (`.text`, `.rdata`, `.data`, `.idata`, `.reloc`, `.symtab`, `.rsrc`) |
| Entry Point | `0x6B380` |
| Compile Timestamp | **Zeroed** — `1970-01-01 00:00:00` (anti-forensics) |
| OS Target | Windows 6.1+ (Windows 7) |
| Subsystem | Windows GUI |
| Linker | Go toolchain (Linker v3.0) |
| Compiler | **Go 1.25.9** |
| Obfuscator | **garble** (confirmed via YARA `Warp`/`WarpStrings` rules) |
| Digital Signature | Invalid WIN_CERTIFICATE (fake/stripped) |
| Packer | None detected |

---

## Build Artifacts

Recovered from `.data` section Go `buildinf` structure:

```
go1.25.9
-buildmode=exe
-compiler=gc
-trimpath=true          ← source path stripping
CGO_ENABLED=0           ← pure Go, no CGO
GOARCH=386
GOOS=windows
GO386=sse2
```

Go Build ID: `Ewx3FhaRdsXQrLlIjDFd/ioJvzrD9QjEmk0Zl4n2c/UxTXMfM6JneLCdG9unQ6/TWPKoYJzbTBb6A_c22Fp`

`-trimpath=true` removes all source paths from the binary, preventing path-based analyst pivoting. Combined with garble, COFF symbol table contains **zero non-runtime symbols**.

---

## Infection Mechanism

The binary is a standalone `.exe` dropped and executed by a delivery mechanism (not present in this sample). Upon execution:

1. **Go runtime initialisation** — standard Go goroutine scheduler and GC start
2. **Anti-analysis checks** — software breakpoint detection via INT3 scanning; debugger exception handler installed (vectored SEH); console control handler registered
3. **Config decryption** — embedded config blob decrypted at runtime using RC4/ChaCha20; no plaintext C2 strings recoverable statically
4. **Process enumeration** — `CreateToolhelp32Snapshot` enumerates running processes (likely for injection target selection or AV/EDR detection)
5. **PPID spoofing setup** — `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute` configures a spoofed parent PID to disguise process creation
6. **Process injection** — thread context hijacking into a target process:
   - `OpenProcess` → acquire handle to target
   - `VirtualAlloc` → allocate RWX memory in target
   - `SuspendThread` → freeze target thread
   - `GetThreadContext` → read thread registers
   - `SetThreadContext` → redirect EIP/RIP to injected shellcode
   - `ResumeThread` → execute injected code
7. **C2 beacon** — TCP/UDP/DNS communications to encrypted C2 endpoint

---

## Capabilities

### Cryptography (CAPA confirmed)
| Algorithm | Use |
|-----------|-----|
| ChaCha20 / Salsa20 | Primary C2 comms encryption or payload decryption |
| AES (x86 AESNI extensions) | Secondary encryption layer |
| RC4 PRGA | Config blob / string decryption |
| MurmurHash3 | Hash-based dispatch / lookup tables |
| QuickLZ | Payload / traffic compression |

Constants `expand 32-byte k` / `expand 16-byte k` (ChaCha20/Salsa20 sigma constants) confirmed in `.text`.

### Process Injection
- Thread context hijacking (classic `SuspendThread` → `GetThreadContext` → patch EIP → `SetThreadContext` → `ResumeThread`)
- PPID spoofing via `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute`
- `CreateToolhelp32Snapshot` + `Process32First/Next` for target process enumeration

### Networking
- Full Winsock2 stack: TCP connect, TCP **listen** (can act as reverse/bind shell), UDP socket, DNS resolution
- `DnsQuery_W` / `DnsRecordListFree` — direct DNS API (DNS-over-system for C2 or DNS tunnelling)
- `WSASend` / `WSARecv` / `WSARecvFrom` — async I/O
- `TransmitFile` — file transfer over socket
- `GetAddrInfoW` — hostname resolution
- `CertFreeCertificateChain` — TLS/HTTPS certificate validation (likely HTTPS C2)
- `bcryptprimitives.dll` — Windows BCrypt for TLS crypto

### Defense Evasion
| Technique | Evidence |
|-----------|----------|
| Garble obfuscation | YARA `Warp`/`WarpStrings`; all function/type names randomised |
| Source path stripping | `-trimpath=true` build flag |
| Timestamp zeroing | PE timestamp = `1970-01-01` |
| Fake signature | Invalid `WIN_CERTIFICATE` structure |
| Software breakpoint detection | CAPA `check for software breakpoints` (B0001.025) |
| Debugger exception handler | YARA `DebuggerException__SetConsoleCtrl` |
| Vectored SEH | YARA `SEH__vectored` |
| Runtime API resolution | PEB walk (`RtlGetCurrentPeb` + 42 PE export resolutions via CAPA) |
| Dynamic library loading | `LoadLibraryW` / `LoadLibraryExW` |
| PE section enumeration | CAPA 5 matches — likely for EDR memory scanning detection |

### Token / Privilege Manipulation
- `GetTokenInformation` — inspect process/thread token (privilege checking or token impersonation prep)
- `LookupAccountSidW` / `GetLengthSid` — SID operations

### Discovery
- `CreateToolhelp32Snapshot` — process list enumeration
- `GetUserProfileDirectoryW` — user profile path discovery
- `GetProcessAffinityMask` — CPU affinity / sandbox detection
- `GetSystemInfo` / `GetSystemDirectoryA` — system fingerprinting
- `DnsQuery_W` — DNS-based network discovery

### Persistence (suspected — config encrypted)
- `win_registry` YARA match → registry key operations present
- `CreateSymbolicLinkW` — possible symlink-based persistence
- `SetFileTime` — file timestomping

### File Operations
- `CreateFileW` / `DeleteFileW` / `SetFileTime` — file creation, deletion, timestomping
- `GetFinalPathNameByHandleW` — path resolution
- `TransmitFile` — file exfiltration over socket

---

## Obfuscation Details

### Garble (Go code obfuscator)
All non-runtime symbols renamed to random strings. Recovered garble names:

**Functions (from `redress src`):**
| Garble Name | Source Lines | Estimated Role |
|-------------|-------------|----------------|
| `kikhalbiibbgb` | 196–5124 (4928 lines) | Initialisation / setup |
| `main` | 5124–26064 (20940 lines) | Core implant logic (monolithic) |
| `lllubsympaoflix` | 26064–35900 (9836 lines) | C2 comms handler |
| `zthivflc` | 35900–48211 (12311 lines) | Crypto/decryption |
| `uvtzoducmf` | 48211–59244 (11033 lines) | Injection engine |
| `rvnqqqbdghyw` | 59244–61701 (2457 lines) | Process enumeration |
| `juswajjmocosjd` | 61701–65387 (3686 lines) | Persistence / registry |
| `srinlrbeo` | 65387–83786 (18399 lines) | Command dispatch |

**API stub names (garble-renamed exports):**
`Acruntlhzqmetj`, `Anvireg`, `Bygnudpvynn`, `Cngtpvjpyll`, `Ftpbhzaleuj`, `Fudftpcjsa`, `Hopoarunkumih`, `Rtloadpgfvwvjvt`, `Vymscngiu`

**Custom type descriptors (from .rdata):**
- `main.Ccjaqdvdlfbuja` — config/connection slot struct; allocated as arrays of **1232** and **3600** entries
- `main.Ioepwyttnmuvp` — secondary struct (agent/session state)

---

## Static Analysis Summary (CAPA / YARA)

### CAPA — ATT&CK Mappings
| Tactic | Technique |
|--------|-----------|
| DEFENSE EVASION | T1027 — Obfuscated Files or Information |
| EXECUTION | T1129 — Shared Modules |

### CAPA — MBC Behaviors
| Objective | Behavior |
|-----------|----------|
| ANTI-BEHAVIORAL ANALYSIS | Debugger Detection — Software Breakpoints (B0001.025) |
| CRYPTOGRAPHY | AES (C0027.001), RC4 (C0027.009), RC4 PRGA (C0021.004) |
| CRYPTOGRAPHY | Salsa20/ChaCha20 |
| DATA | QuickLZ decompression (C0025.001) |
| DATA | MurmurHash3 (C0030.001) |
| DISCOVERY | Enumerate PE Sections (B0046.001) |
| DISCOVERY | Inspect Section Memory Permissions (B0046.002) |
| PROCESS | Allocate Thread Local Storage (C0040) |

### YARA Rules Matched
`Warp`, `WarpStrings`, `DebuggerException__SetConsoleCtrl`, `ThreadControl__Context`, `SEH__vectored`, `network_tcp_listen`, `network_tcp_socket`, `network_udp_sock`, `network_dns`, `win_registry`, `win_token`, `win_files_operation`, `Str_Win32_Winsock2_Library`, `Big_Numbers1`, `Big_Numbers3`, `possible_includes_base64_packed_functions`

**Zero matches** in yara-forge (45+ sources including Malpedia, ReversingLabs) → **no known family attribution**.

---

## C2 Infrastructure

**C2 config is fully runtime-decrypted — no plaintext network indicators recoverable statically.**

Evidence of encryption:
- RC4 + ChaCha20/AES crypto stack with no plaintext keys or endpoints
- All strings in `.rdata` are Go runtime or garble-renamed
- `.data` section entropy consistent with Go global variables only
- xorsearch false positives only (Go runtime code fragments)
- No IP addresses, domains, or URLs found in any section

C2 transport indicators:
- TCP (primary — likely HTTPS given `CertFreeCertificateChain`)
- UDP socket (secondary)
- DNS queries (`DnsQuery_W`) — possible DNS-over-HTTPS or DNS tunnelling fallback
- TCP listen capability — supports **reverse AND bind** modes

---

## Resources

| Type | Name | Size | Notes |
|------|------|------|-------|
| ICON | #1 | 1,128 B | BMP 32×64 px |
| ICON | #2 | 16,936 B | BMP 64×128 px |
| ICON | #3 | 67,624 B | BMP 128×256 px |
| ICON | #4 | 34,662 B | **PNG 256×256 RGBA** — valid image, no appended data, no LSB stego |
| GROUP_ICON | MAINICON | 62 B | Standard icon group |

PNG (ICON #4): SHA256 `183e79c0efcad224e98f05814ac825efa21a0b886bef0fa19237c33a927d494c` — clean; high entropy (7.98) explained by zlib compression within PNG IDAT chunks. No appended data, no text chunks, no LSB steganography detected.

---

## Indicators of Compromise

### File Hashes
```
MD5:    51fe8e4c8974c3a1098784da1b195f1d
SHA1:   023ff6ba089f30ec1e1f3fc471478baabebc5be2
SHA256: f061a7c86a39411cd19ba983a15953c37df9ce31e6b01babc264421a5658780c
ssdeep: 49152:RGPGTIlZrHmlSdyGUDRKygzkjiNwLz2IL3zbslT1RROzmJ3pxab4JqaHpbn47qKA:o4IlZjmlmyGUDRKyg4kMnslTvQzmJ3pt
```

### Network IOCs
None recoverable statically (all C2 config runtime-encrypted).

### Build-Level IOCs (unique to this binary / campaign)
```
Go Build ID:  Ewx3FhaRdsXQrLlIjDFd/ioJvzrD9QjEmk0Zl4n2c/UxTXMfM6JneLCdG9unQ6/TWPKoYJzbTBb6A_c22Fp
Compiler:     go1.25.9
Build flags:  -trimpath=true, CGO_ENABLED=0, GOARCH=386, GOOS=windows
```

### Behaviour-Based IOCs (hunt in EDR/SIEM)
- PE32 GUI process with `SuspendThread` + `GetThreadContext` + `SetThreadContext` + `ResumeThread` in the same execution context
- `InitializeProcThreadAttributeList` followed immediately by `UpdateProcThreadAttribute` (PPID spoofing)
- `CreateToolhelp32Snapshot` from a GUI process with no visible window
- `DnsQuery_W` called directly (not through standard resolver APIs)
- Go binary with zeroed PE timestamp + `powrprof.dll` import
- Process creating a TCP listener with no corresponding window handle

### Garble Obfuscation Fingerprints (YARA hunting)
- Rule: `Warp` / `WarpStrings`
- Type descriptors: `main.Ccjaqdvdlfbuja`, `main.Ioepwyttnmuvp` (may vary per build)

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|----|-----------|
| Execution | T1129 | Shared Modules |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1027.007 | Dynamic API Resolution (PEB walk) |
| Defense Evasion | T1036 | Masquerading (fake certificate, zeroed timestamp) |
| Defense Evasion | T1134.004 | Parent PID Spoofing |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion — System Checks |
| Defense Evasion | T1070.006 | Timestomp |
| Privilege Escalation | T1134 | Access Token Manipulation |
| Discovery | T1057 | Process Discovery |
| Discovery | T1082 | System Information Discovery |
| Discovery | T1033 | System Owner/User Discovery |
| Injection | T1055.003 | Thread Execution Hijacking |
| C2 | T1071.001 | Application Layer Protocol — Web (HTTPS likely) |
| C2 | T1071.004 | Application Layer Protocol — DNS |
| C2 | T1573 | Encrypted Channel |

---

## Risk Assessment

**Overall Risk: CRITICAL**

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Sophistication | HIGH | Go + garble + multi-crypto stack + PPID spoofing; build OPSEC |
| Evasion | HIGH | No family signatures; zeroed timestamp; fake cert; runtime config decryption; trimpath |
| Impact | CRITICAL | Full remote code execution via process injection; C2 with TCP listen/connect; token manipulation |
| Attribution | LOW confidence | No known family; novel tooling; no infrastructure; style consistent with nation-state or advanced criminal operator |
| Detection | DIFFICULT | No static C2 IOCs; garble prevents signature-based detection; PPID spoofing evades parent-process heuristics |

---

## Analyst Notes & Limitations

1. **C2 not recovered** — runtime decryption prevents static extraction. Dynamic analysis (sandbox with network capture) or memory forensics post-infection required to extract C2 endpoints.
2. **No family attribution** — zero YARA-forge matches across 45+ sources. This is either a new family, a heavily modified fork, or a purpose-built custom tool.
3. **Speakeasy emulation failed** — Go runtime initialization crashes the emulator at `0x4349d0`; behavioral data from emulation is unavailable.
4. **FLOSS crashed** — Go 1.25.9 + garble exceeds FLOSS rendering capacity; no stack-assembled string recovery possible.
5. **Type array sizes 1232 and 3600** — suggest structured connection pool or timed-beacon config (3600 = 1 hour interval). Warrants further reverse engineering in Ghidra/IDA.
6. **`powrprof.dll`** — unusual import for a network implant; may indicate sleep/wake triggers based on power events, or used as a LOLbin load vector.

---

## Recommended Actions

1. **Sandbox execution** with full network capture (FakeNet-NG or INetSim) to extract live C2 endpoint
2. **Memory dump** of infected process for config extraction post-injection
3. **Ghidra/IDA analysis** of `srinlrbeo` (18,399-line command dispatch) and `main` (20,940-line core) using Go type recovery plugins
4. **Hunt on YARA `Warp`/`WarpStrings`** across endpoint telemetry
5. **EDR rules**: alert on GUI PE + `SuspendThread`/`GetThreadContext`/`SetThreadContext` chain + `InitializeProcThreadAttributeList` in same process
6. **DNS monitoring**: `DnsQuery_W` direct calls bypassing system resolver — unusual in legitimate software
7. **Block** SHA256 `f061a7c86a39411cd19ba983a15953c37df9ce31e6b01babc264421a5658780c` across endpoint controls
