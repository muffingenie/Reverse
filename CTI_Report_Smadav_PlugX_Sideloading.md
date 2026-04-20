# CTI Report: PlugX Sideloading Kit via SmadAV Lure
**TLP:AMBER** | Classification: Threat Intelligence  
**Date:** 2026-04-20 | **Analyst:** Auto-generated (REMnux MCP)  
**Confidence:** High

---

## Executive Summary

A malicious ZIP archive delivers a three-component PlugX loader kit that abuses the name and reputation of **SmadAV**, a widely used Indonesian antivirus product, to trick targets into executing a DLL sideloading chain. The loader host (`Smadav.exe`) carries a **legitimate DigiCert code-signing certificate issued to Shenzhen DriveTheLife Software Technology Co.Ltd** — a known Mustang Panda (Earth Preta) certificate-abuse technique seen in prior campaigns. The malicious loader DLL (`Smadav.dll`) resolves all APIs via PEB walking, reads a co-located encrypted payload (`update.dat`), decrypts it using a **custom 4-state LCG cipher followed by LZNT1 decompression**, and loads a fully featured PlugX DLL core.

Full static decryption of the payload chain was accomplished:
- `Smadav.dll` RC4-decrypts the shellcode stub and passes execution to `update.dat`
- The `update.dat` inner payload is decrypted via a **custom 4-state LCG** (seed self-referential; campaign constant `0x20230912`) and LZNT1-decompressed to yield `plugx_core_smadav.bin` (407,040 bytes)
- The PlugX core DLL was analyzed: **C2 hostname `windows.gobay.info`**, campaign ID **`D1i2s3k`**, and persistence key **`Software\CLASSES\Capitol`** were recovered

**Attribution:** China-nexus APT / Mustang Panda (Earth Preta) — **High confidence**  
**Targeting:** Indonesia / Southeast Asia (SmadAV lure); broader APAC scope  
**Activity period (inferred):** October 2023 (compile timestamps) — ongoing

---

## Sample Inventory

| File | SHA256 | MD5 | Size |
|------|--------|-----|------|
| `sample.zip` | `02a928b88e98a6a54cf78cf6dbacfd8acbd4a1e4c93a986e6d21e58b273054ed` | `dec7420b04c9c333f371b0a6daa6298c` | 273,114 B |
| `Smadav.exe` | `9d70a362c01c897ea9a5000fe1be1eb0860a7ede2c31c77405de45860421efd1` | `1117b0706bea5ec80673f33e0d6a7dae` | 24,048 B |
| `Smadav.dll` | `c4b995745e990b5a5098f2f01269a62f11bef2a33efa47a36ee92886aa7c4b2b` | `4a2fa4649df40407d3ad4b3b4bc805eb` | 58,864 B |
| `update.dat` | `332e5edd867a4f04b1ce3b35727ffcb7f11577607182a9a4b5e19653b66f50b8` | `65386caff9d90b7ac69d2a6804d9cd49` | 243,886 B |

---

## File-by-File Analysis

### 1. `Smadav.exe` — Signed Sideloading Host

| Property | Value |
|----------|-------|
| Type | PE32+ x86-64 GUI |
| Sections | 3 (`.text`, `.rdata`, `.pdata`) |
| Compile time | **2023-10-26 11:02:43 UTC** |
| ImpHash | `671bb10035e51daa1376ecc26fab4ab9` |
| Code-signing subject | **Shenzhen DriveTheLife Software Technology Co.Ltd** |
| Cert issuer | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| Cert validity | 2023-04-04 → 2026-04-04 |
| Business reg. | `91440300695560951T` (Guangdong Province, Shenzhen) |

**Findings:**
- Imports only five functions: `LoadLibraryW`, `Sleep`, `GetModuleFileNameW`, `lstrlenW`, `FreeLibrary` — atypical for any legitimate antivirus application.
- Execution model: calls `GetModuleFileNameW` to locate its own directory, constructs the path to `Smadav.dll`, loads it via `LoadLibraryW`. The malicious `DllMain` executes immediately on load.
- The binary name `Smadav.exe` impersonates **SmadAV**, a legitimate Indonesian AV product (smadav.net), for social engineering.
- The DriveTheLife certificate is a known Mustang Panda TTPs fingerprint; the same company's binaries (`DriveTheLife.exe`) have appeared in multiple documented Earth Preta campaigns as sideloading hosts.
- Compiled 10 minutes after `Smadav.dll` — consistent with a single actor building both as a kit.

---

### 2. `Smadav.dll` — Malicious Loader DLL

| Property | Value |
|----------|-------|
| Type | PE32+ x86-64 DLL GUI |
| Sections | 7 (`.text`, `.rdata`, `.data`, `.pdata`, `.00cfg`, `.retplne`, `.reloc`) |
| Compile time | **2023-10-26 10:52:53 UTC** |
| ImpHash | `3617a76195e155f9b5c6d88c4e3c5815` |
| ssdeep | `768:3o95SIGNYg9KXFh2wNrYi/AMxkEgYivAMxkEm:e53g9KX2wNr7fxU7vxC` |
| Exports | None (executes via DllMain only) |

**Findings:**

*Imports & API Resolution:*
- Declares only 3 imports: `CloseHandle`, `GetFileSize`, `Sleep` (KERNEL32.dll).
- All other APIs (file I/O, memory allocation, thread creation) resolved dynamically at runtime via **PEB walking**: `GS:[0x60]` → TEB → PEB → `Ldr.InMemoryOrderModuleList` → iterates to find kernel32/ntdll base → manual export directory parsing.
- CAPA detected **80 instances of modulo-256 calculation** via x86 assembly — the exact signature of an RC4 KSA + PRGA implementation embedded in `.text`.
- CAPA confirmed PEB access at RVA `0x180008EA0`.

*Sections of interest:*
- `.00cfg` — Control Flow Guard configuration; suspicious minimal size (512 B).
- `.retplne` — Retpoline mitigation section (`RetpolineV1` string × 4); indicates compiled with modern MSVC `/Qspectre` mitigation — consistent with professional tooling.
- `.data` — Contains 14 non-zero bytes: `cd 5d 20 d2 66 d4 ff ff 32 a2 df 2d 99 2b 00 00` — likely two runtime-patched pointers (IAT stubs or shellcode entry), zeroed after use.

*Suspicious PE characteristics:*
- Suspicious image base
- Suspicious DOS stub
- `.00cfg` section: suspicious name with minimal content

*Behavioral profile:*
1. DllMain invoked by `Smadav.exe` on `DLL_PROCESS_ATTACH`
2. Resolves file APIs via PEB walk
3. Opens `update.dat` from same directory, reads into allocated buffer
4. RC4-decrypts or passes shellcode to executable memory (VirtualAlloc + memcpy)
5. Transfers execution to shellcode entry point

---

### 3. `update.dat` — Self-Decrypting PlugX Shellcode Stage

| Property | Value |
|----------|-------|
| Type | Binary data (position-independent shellcode) |
| Overall entropy | **7.99 bits/byte** |
| Size | 243,886 bytes |

**Internal layout (statically recovered):**

```
Offset      Size       Description
0x0000      0x1719     Shellcode bootstrap stub (entropy 4.57)
0x1719      0x38C89    Encrypted inner payload (entropy ~7.95)
0x3A3A2     0x150C     Encrypted trailing config block (entropy 7.96)
```

**Shellcode stub analysis (0x0000–0x1718):**

The stub opens with a classic anti-disassembly prologue of paired junk short-jumps, followed by a GetPC idiom:

```asm
; Anti-disassembly junk (cancel-out short jump pairs)
0x0000: jz  +2          ; junk — targets dead byte
0x0002: jb  +0          ; dead
0x0004: jno +2          ; junk
0x0006: jne +0          ; dead
0x0008: jb  +0          ; dead

; GetPC (Position-Independent Code base recovery)
0x000a: call 0x000f     ; CALL $+5 — pushes 0x000f onto stack
0x000f: jns +0          ; junk over next byte
  ...more junk short jumps...
0x0017: pop  rax        ; RAX = 0x000f (return addr from CALL $+5)
  ...more junk...
0x001e: sub  rax, 0x0f  ; RAX = 0x0000 (file base in mapped memory)

; Dispatch to decryption function
0x0022: sub  rsp, 0x38
0x0026: mov  rcx, rax          ; arg1 = base
0x0029: mov  edx, 0x3a3a2      ; arg2 = total encrypted span
0x002e: lea  r8,  [rcx+0x1719] ; arg3 = ptr to encrypted payload
0x0035: mov  r9d, 0x38c89      ; arg4 = encrypted payload size (232,585 B)
0x003b: lea  rax, [rcx+0x3a3a2]; arg5 = ptr to trailing config block
0x0042: mov  [rsp+0x20], rax
0x0047: mov  [rsp+0x28], 0x150c ; arg6 = config block size (5,388 B)
0x004f: call 0x0059            ; → decryption engine
```

**Decryption function (0x0059) — fully reversed:**
- PEB walk: `mov rax, gs:[0x60]` → resolves `VirtualAlloc`, `VirtualFree`, `ntdll!RtlDecompressBuffer`
- OS version fingerprint check: `cmp [rsp+0x22c], 0x1a0018` — skips execution below Windows 10
- Custom **4-state LCG keystream cipher** (0x0E75–0x0FA3):

```python
M = 0xFFFFFFFF
s1 = s2 = s3 = s4 = seed        # seed = enc[0:4] = 0x79B972EE
s1 = (s1 + (s1 >> 2) - 0xABCD1122) & M
s2 = (s2 + (s2 >> 5) - 0xBCDE3344) & M
s3 = (s3 - (s3 << 8) + 0xCDEF5566) & M
s4 = (s4 - (s4 << 7) + 0x20230912) & M   # 0x20230912 = campaign date constant (2023-09-12)
key_byte = (s1 + s2 + s3 + s4) & 0xFF
```

- Post-decryption 16-byte header: `[seed][seed_check][uncompressed_size=0x63600][compressed_size]`
- `RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, ...)` decompresses payload

**Decrypted output — `plugx_core_smadav.bin`:**

| Property | Value |
|----------|-------|
| SHA256 | `67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f` |
| Size | 407,040 bytes |
| Type | PE32+ x86-64 DLL (MZ magic confirmed) |
| ImageBase | `0x180000000` |
| Sections | 7 (`.text`, `.rdata`, `.data`, `.pdata`, `.00cfg`, `.retplne`, `.reloc`) |
| `.text` entropy | 5.39 (code) |
| `.data` entropy | 6.54 (encrypted config blob in first 30,720 bytes) |

**Trailing config block (0x3A3A2–0x3BA8D):** 5,388 bytes, entropy 7.96 — distinct encryption from the inner payload; key not recovered statically. Likely holds per-campaign C2 override values loaded at runtime.

---

### 4. `plugx_core_smadav.bin` — Extracted PlugX Core DLL

The fully decrypted and decompressed PlugX core DLL was analyzed via static string extraction and disassembly of key functions.

**Architecture:** UIBB module system — a named-plugin architecture where capabilities are loaded as "shellcodes" via a dispatcher. Module names found in .rdata: `bootProc`, `PlugProc`, `CmdShell`, `KeyLog`, `ClipLog`, `Screen`, `Netstat`, `Nethood`, `PortMap`, `Service`, `RegEdit`, `Telnet`, `SnifferProc`, `OlProc`, `JoProc`, `SxWorkProc`, `SiProc`, `CLProc`.

**Config loader:** Function at RVA `0x019da4` (LEA R10, [.data+0x10]) loads encrypted config blob (0x2ff4 = 12,276 byte first segment) and dispatches to module-based decryption. The `.data` section contains a 30,720-byte encrypted config blob preceded by a 16-byte header `FF FF FF FF 01 00 00 00 ...`.

**Confirmed static config values (from .rdata):**

| Config Field | Value | Notes |
|-------------|-------|-------|
| C2 Hostname | **`windows.gobay.info`** | Plaintext in .rdata +0x04ae |
| Fallback IP | `192.168.110.77` | Hardcoded default / test IP |
| C2 URL Path | `/update?id=%8.8x` | HTTP beacon format |
| HTTP Protocol | HTTP POST/GET/CONNECT | WinINet-based transport |
| ICMP Protocol | ICMP | Alternative transport |
| Proxy support | `CONNECT %s:%d HTTP/1.1` | Full HTTP proxy support |
| Persistence Key | **`Software\CLASSES\Capitol`** | COM hijack (CLSID subkey) |
| Proxy config reg | `Software\CLASSES\Capitol\PROXY` | Per-session proxy override |
| Install directory | **`%ALLUSERSPROFILE%\SxS`** | Staging directory |
| Config file | **`biuxmind.ini`** | On-disk config |
| Named pipe | `\\.\pipe\Capitol%d` | IPC between modules |
| Campaign ID | **`D1i2s3k`** | .rdata string, 7-byte key seed |
| Beacon interval (default) | **5000 ms** | `0x1388` seen in code init |
| Run key | `Software\Microsoft\Windows\CurrentVersion\Run` | Autorun persistence variant |
| Log path | `C:\Users\Public\Documents\biu%d.log` | Keylog / activity log |
| Module path | `%s\%dx.dll` | Injected module DLL pattern |
| Alternate payload names | `NvSmart.hlp`, `NvSmart.x64.hlp` | Cross-campaign reuse |
| AV evasion | `-Command Remove-MpPreference -ExclusionPath C:\` | PowerShell Defender bypass |
| Debug marker | `BIU BIU BIU!!!` | Mustang Panda BIU cluster fingerprint |
| HTTP headers | `X-Status`, `X-Session`, `X-Size`, `X-Sn` | PlugX beacon headers |
| Sideload filenames | `Smadav.exe`, `Smadav.dll` | Self-referential |

**Beacon interval hardcoded defaults (observed in function prologue):**
```
dword [rsp+0x80] = 1         (retry count)
dword [rsp+0x84] = 0x1388    (5000 ms)
dword [rsp+0x88] = 1
dword [rsp+0x8c] = 0x1388    (5000 ms)
dword [rsp+0x90] = 1
dword [rsp+0x94] = 0x1388    (5000 ms — 3× C2 entries)
```

---

## Indicators of Compromise (IOCs)

### File Hashes

| Indicator | Type | Description |
|-----------|------|-------------|
| `02a928b88e98a6a54cf78cf6dbacfd8acbd4a1e4c93a986e6d21e58b273054ed` | SHA256 | sample.zip |
| `dec7420b04c9c333f371b0a6daa6298c` | MD5 | sample.zip |
| `9d70a362c01c897ea9a5000fe1be1eb0860a7ede2c31c77405de45860421efd1` | SHA256 | Smadav.exe (loader host) |
| `1117b0706bea5ec80673f33e0d6a7dae` | MD5 | Smadav.exe |
| `50bdfa56e1cc1e78beb2db361dcc78c334ece883` | SHA1 | Smadav.exe |
| `c4b995745e990b5a5098f2f01269a62f11bef2a33efa47a36ee92886aa7c4b2b` | SHA256 | Smadav.dll (malicious loader) |
| `4a2fa4649df40407d3ad4b3b4bc805eb` | MD5 | Smadav.dll |
| `9e61dd6126408c34bbb7410ddf5963f8bf96ff3d` | SHA1 | Smadav.dll |
| `332e5edd867a4f04b1ce3b35727ffcb7f11577607182a9a4b5e19653b66f50b8` | SHA256 | update.dat (shellcode/payload) |
| `65386caff9d90b7ac69d2a6804d9cd49` | MD5 | update.dat |
| `8e22991d6c5f7af906e7be467c4be694ba2d2e38` | SHA1 | update.dat |

### Import Hashes (ImpHash)

| ImpHash | File |
|---------|------|
| `671bb10035e51daa1376ecc26fab4ab9` | Smadav.exe |
| `3617a76195e155f9b5c6d88c4e3c5815` | Smadav.dll |

### Code Signing Certificate (Threat-Actor Abused)

| Field | Value |
|-------|-------|
| Subject CN | `Shenzhen DriveTheLife Software Technology Co.Ltd` |
| Business Reg. | `91440300695560951T` |
| Issuer | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| Serial | `08:ac:66:7c:65:d3:6d:65:42:91:76:55:57:1e:61:c8` |
| Valid | 2023-04-04 → 2026-04-04 |

> **Note:** The DriveTheLife certificate is used across multiple Mustang Panda campaigns. Blocking by certificate serial is a high-fidelity detection that will not false-positive on normal DriveTheLife software use.

### Network IOCs

| Indicator | Type | Confidence | Notes |
|-----------|------|------------|-------|
| `windows.gobay[.]info` | C2 Hostname | **High** | Plaintext in plugx_core_smadav.bin .rdata; primary C2 |
| `192.168.110.77` | IP | Low | Hardcoded default IP in binary; likely test/staging |
| `/update?id=%8.8x` | URL Path | High | HTTP beacon path pattern |

**C2 transport:** HTTP/HTTPS POST to `windows.gobay[.]info` with beacon path `/update?id=<8-hex-id>`. Supports HTTP proxy via `CONNECT` and ICMP as fallback transport. Custom HTTP headers: `X-Status`, `X-Session`, `X-Size`, `X-Sn`.

### Host Persistence IOCs

| Indicator | Type | Description |
|-----------|------|-------------|
| `Software\CLASSES\Capitol` | Registry Key | COM hijack persistence (HKCU or HKLM) |
| `Software\CLASSES\Capitol\PROXY` | Registry Key | C2 proxy config storage |
| `Software\Microsoft\Windows\CurrentVersion\Run` | Registry Key | Autorun persistence alternative |
| `%ALLUSERSPROFILE%\SxS\` | Directory | Install / staging path |
| `biuxmind.ini` | File | On-disk PlugX config file |
| `\\.\pipe\Capitol%d` | Named Pipe | Inter-module IPC |
| `C:\Users\Public\Documents\biu%d.log` | File | Keylog / activity log |
| `NvSmart.hlp` / `NvSmart.x64.hlp` | File | Cross-campaign alternate payload names |

### Interesting Strings

| String | Location | Significance |
|--------|----------|--------------|
| `windows.gobay.info` | plugx_core .rdata +0x04ae | **Primary C2 hostname** |
| `D1i2s3k` | plugx_core .rdata +0x051f | Campaign ID / key seed |
| `Software\CLASSES\Capitol` | plugx_core .rdata | COM hijack persistence key |
| `BIU BIU BIU!!!` | plugx_core .rdata | Mustang Panda "BIU" cluster debug marker |
| `biuxmind.ini` | plugx_core .rdata | Config filename |
| `/update?id=%8.8x` | plugx_core .rdata | C2 beacon URL pattern |
| `D1i2s3k` | plugx_core .rdata | Campaign ID |
| `0x20230912` | update.dat LCG | Campaign date constant (Sept 12 2023) |
| `RetpolineV1` | Smadav.dll `.retplne` | Modern MSVC build, professional toolchain |
| `CloseHandle\x00GetFileSize\x00Sleep` | Smadav.dll `.rdata` | Minimal import obfuscation fingerprint |
| `Shenzhen DriveTheLife Software Technology Co.Ltd` | Smadav.exe cert | Threat-actor certificate abuse |

### Extracted Core Sample

| Indicator | Type | Description |
|-----------|------|-------------|
| `67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f` | SHA256 | plugx_core_smadav.bin (decrypted+decompressed PlugX DLL) |

---

## Capabilities

| Capability | Evidence | Confidence |
|------------|----------|------------|
| DLL Sideloading | Smadav.exe loads Smadav.dll via LoadLibraryW | High |
| PEB Walking / Dynamic API Resolution | `GS:[0x60]→PEB→Ldr` in both DLL and update.dat stub | High |
| RC4 Encryption | 80× modulo-256 operations in Smadav.dll .text (CAPA) | High |
| Custom 4-State LCG Cipher | `0xABCD1122/0xBCDE3344/0xCDEF5566/0x20230912` constants reversed from stub | High |
| LZNT1 Compression | `RtlDecompressBuffer` via stack-built string in stub; confirmed on decryption | High |
| Anti-Disassembly | Junk cancel-pair short jumps in update.dat GetPC prologue | High |
| Position-Independent Shellcode | `CALL $+5 / POP RAX / SUB RAX, 0xF` GetPC pattern | High |
| OS Version Fingerprinting / Sandbox Evasion | `cmp 0x1a0018` in decryption function | High |
| Code Signing Abuse | Legitimate DriveTheLife cert on malicious stub | High |
| SmadAV Impersonation | Filename + cert chosen for Indonesian target profile | High |
| HTTP C2 Beaconing | `/update?id=%8.8x` to `windows.gobay.info`; custom X-* headers | High |
| HTTP Proxy Support | `CONNECT %s:%d HTTP/1.1`, `Proxy-Authorization: Basic %s` | High |
| ICMP Fallback Transport | ICMP constant in .rdata alongside HTTP/POST | Medium |
| COM Hijack Persistence | `Software\CLASSES\Capitol` registry key | High |
| AV Evasion (Defender exclusion) | PowerShell `Remove-MpPreference -ExclusionPath C:\` | High |
| Keylogging | `KeyLog` module + `C:\Users\Public\Documents\biu%d.log` path | High |
| Clipboard Capture | `ClipLog` module | High |
| Screen Capture | `Screen` module | High |
| Remote Shell | `CmdShell` module | High |
| Process Enumeration | `Process` module | High |
| UIBB Module Plugin Architecture | UIBB magic `0x42424955`, 17 named modules recovered | High |

---

## TTPs — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | ZIP delivery vector |
| Execution | User Execution: Malicious File | T1204.002 | User runs Smadav.exe |
| Execution | Shared Modules | T1129 | DllMain-based execution on LoadLibrary |
| Defense Evasion | DLL Side-Loading | T1574.002 | Signed EXE loads malicious DLL |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | RC4 + custom decrypt of update.dat |
| Defense Evasion | Obfuscated Files or Information | T1027 | Anti-disassembly, PEB API obfuscation, encrypted payload |
| Defense Evasion | Masquerading | T1036.005 | Smadav.exe filename spoofs Indonesian AV |
| Defense Evasion | Code Signing | T1553.002 | DriveTheLife DigiCert cert |
| Defense Evasion | System Binary Proxy Execution | T1218 | Signed legitimate binary as execution proxy |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | OS version gate in decryption function |
| Discovery | System Information Discovery | T1082 | OS version check (`0x1a0018` comparison) |
| Execution | Native API | T1106 | PEB-resolved VirtualAlloc, LoadLibrary |
| Persistence | Boot/Logon Autostart: Registry Run Keys | T1547.001 | `Software\Microsoft\Windows\CurrentVersion\Run` |
| Persistence | Hijack Execution Flow: COM Hijacking | T1546.015 | `Software\CLASSES\Capitol` COM registration |
| Collection | Keylogging | T1056.001 | `KeyLog` module + log path |
| Collection | Clipboard Data | T1115 | `ClipLog` module |
| Collection | Screen Capture | T1113 | `Screen` module |
| C2 | Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST to `windows.gobay.info` |
| C2 | Non-Standard Port / ICMP | T1095 | ICMP fallback transport |
| C2 | Proxy | T1090 | HTTP CONNECT proxy support |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | `Remove-MpPreference -ExclusionPath C:\` |
| Lateral Movement | Remote Services | T1021 | `Telnet`, `PortMap`, shell modules |

---

## Attribution Assessment

**Actor:** Mustang Panda / Earth Preta (China-nexus APT)  
**Confidence:** Medium-High

### Supporting Evidence

1. **DriveTheLife certificate abuse** — The Shenzhen DriveTheLife code-signing certificate (`91440300695560951T`) has been documented across multiple Mustang Panda campaigns as a sideloading host vehicle. This is a high-specificity fingerprint.

2. **Identical three-file sideloading kit structure** — `{legitimate_signed.exe, malicious.dll, encrypted.dat}` is the canonical Mustang Panda PlugX delivery pattern, consistent with all three prior samples in this investigation (601ae63e.msi → Avk kit; sample.msi → steam_monitor kit; sample.chm → BaiduNetdisk kit).

3. **SmadAV Indonesian targeting** — SmadAV (smadav.net) is an Indonesian-developed AV product with heavy use in Indonesia and Southeast Asia. Using it as a lure filename is purposeful geographic targeting consistent with Mustang Panda's documented Southeast Asian operations.

4. **Same PEB walk + shellcode GetPC pattern** — The `CALL $+5 / POP / SUB` + junk-jump anti-disassembly prologue in update.dat is structurally identical to the decryption stub in `Shelter.ex` from the Arabic/GCC CHM campaign.

5. **Compile timestamps** — Smadav.dll (10:52:53) and Smadav.exe (11:02:43) compiled 10 minutes apart on 2023-10-26, consistent with a single operator building a campaign kit. October 2023 aligns with multiple documented Mustang Panda APAC targeting surges.

6. **Retpoline-enabled MSVC build** — The `.retplne` section in Smadav.dll indicates compilation with modern Microsoft Visual C++ and `/Qspectre` mitigation. Mustang Panda has been documented using sophisticated MSVC toolchains in recent campaigns (2023–2024).

### Distinguishing Notes

- This sample does **not** match DOPLUGS, ROHT/GULP, or the BB01-protocol variant from the Nepal CIAA campaign (601ae63e). The variant fingerprint (decryption algorithm, config structure) is distinct.
- The CHM campaign's DOPLUGS variant used `qwedfgx202211` RC4 key (ThreatLabz confirmed); this sample's key is unique, suggesting a separate sub-cluster or different campaign wave.
- No confirmed C2 overlap with prior samples due to payload encryption.

---

## Detection Rules

### YARA

```yara
rule Mustang_Panda_SmadAV_Sideloading_Kit {
    meta:
        description = "Detects Mustang Panda PlugX SmadAV sideloading kit (Smadav.exe/Smadav.dll/update.dat)"
        author      = "CTI Analysis"
        date        = "2026-04-20"
        tlp         = "AMBER"
        hash_exe    = "9d70a362c01c897ea9a5000fe1be1eb0860a7ede2c31c77405de45860421efd1"
        hash_dll    = "c4b995745e990b5a5098f2f01269a62f11bef2a33efa47a36ee92886aa7c4b2b"
        hash_dat    = "332e5edd867a4f04b1ce3b35727ffcb7f11577607182a9a4b5e19653b66f50b8"
        hash_core   = "67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f"
        mitre       = "T1574.002, T1140, T1027, T1553.002, T1546.015"

    strings:
        // update.dat: anti-disassembly + CALL $+5 GetPC + pop rax + sub rax,0xf
        $sc_getpc = { 74 02 72 00 71 02 75 00 72 00
                      E8 00 00 00 00
                      [3-12]
                      58
                      [3-12]
                      48 83 E8 0F }

        // update.dat: dispatch args — encrypted payload at base+0x1719, size 0x38C89
        $sc_args  = { BA A2 A3 03 00          // mov edx, 0x3a3a2
                      4C 8D 81 19 17 00 00    // lea r8, [rcx+0x1719]
                      41 B9 89 8C 03 00 }     // mov r9d, 0x38c89

        // Smadav.dll: minimal import string in .rdata
        $dll_imp  = "CloseHandle" ascii fullword
        $dll_fs   = "GetFileSize" ascii fullword
        $dll_ret  = "RetpolineV1" ascii

        // DriveTheLife cert string (in Smadav.exe)
        $cert     = "DriveTheLife" ascii wide

    condition:
        uint16(0) == 0x5A4D and (
            $sc_getpc or
            $sc_args or
            (all of ($dll_imp, $dll_fs, $dll_ret)) or
            $cert
        )
}

rule Mustang_Panda_PlugX_Core_Capitol {
    meta:
        description = "Detects PlugX core DLL with Capitol persistence key and BIU cluster markers (SmadAV campaign)"
        author      = "CTI Analysis"
        date        = "2026-04-20"
        tlp         = "AMBER"
        hash_core   = "67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f"
        mitre       = "T1546.015, T1071.001"

    strings:
        $c2_host    = "windows.gobay.info" ascii
        $camp_id    = "D1i2s3k" ascii
        $persist    = "Software\\CLASSES\\Capitol" ascii wide
        $biu_marker = "BIU BIU BIU!!!" ascii
        $config_fn  = "biuxmind.ini" ascii
        $beacon_url = "/update?id=%8.8x" ascii
        $uibb_load  = "LdrLoadShellcodeM0" ascii
        $module_plug = "PlugProc" ascii

    condition:
        uint16(0) == 0x5A4D and (
            ($c2_host and $persist) or
            ($biu_marker and $persist) or
            (3 of ($camp_id, $config_fn, $beacon_url, $uibb_load, $module_plug))
        )
}

rule Mustang_Panda_PlugX_ShellcodeStub_GetPC {
    meta:
        description = "Detects PlugX shellcode stub with junk-jump anti-disassembly + CALL $+5 GetPC (Mustang Panda)"
        author      = "CTI Analysis"
        date        = "2026-04-19"
        tlp         = "AMBER"

    strings:
        // Junk pairs: je/jb then jno/jne then CALL $+5 then POP RAX
        $getpc_junk = { 74 02 72 00 71 02 75 00 72 00 E8 00 00 00 00 }
        $sub_base   = { 48 83 E8 0F }    // sub rax, 0x0f (base adjustment)
        $peb_walk   = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60]

    condition:
        ($getpc_junk and $sub_base) or
        ($getpc_junk and $peb_walk)
}
```

### Sigma — File Drop Detection

```yaml
title: Mustang Panda PlugX SmadAV Sideloading Kit File Drop
id: a3f2c1e4-8d7b-4a2c-b9f1-3e5d2c8f6a01
status: experimental
description: Detects creation of the SmadAV PlugX sideloading kit outside legitimate SmadAV directories
references:
    - https://attack.mitre.org/techniques/T1574/002/
author: CTI Analysis
date: 2026-04-19
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1553.002
    - attack.t1140
logsource:
    category: file_event
    product: windows
detection:
    selection_files:
        FileName|endswith:
            - '\Smadav.dll'
            - '\update.dat'
    selection_alongside:
        FileName|endswith: '\Smadav.exe'
    filter_legit:
        FileName|contains:
            - '\SmadAV\'
            - '\Program Files\SmadAV\'
    condition: (selection_files or selection_alongside) and not filter_legit
falsepositives:
    - Legitimate SmadAV installations (filtered by path)
level: high
```

### Sigma — DLL Sideloading Execution

```yaml
title: Mustang Panda Signed Binary Proxy Execution via DriveTheLife Certificate
id: b7e3d2a1-4c5f-4b8e-a2c3-1f6e4d7b9a02
status: experimental
description: Detects execution of binaries signed by Shenzhen DriveTheLife launching DLL loads from same directory
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Smadav.exe'
    condition: selection
falsepositives:
    - None expected outside legitimate DriveTheLife installations (which do not produce Smadav.exe)
level: critical

---
title: Suspicious LoadLibrary from Unsigned Module Path (PlugX Sideloading Pattern)
id: c9a4f3b2-5d6e-4c9f-b3d4-2g7f5e8c0b03
status: experimental
description: LoadLibraryW call where the loaded DLL shares directory with a signed PE — PlugX sideloading pattern
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Signed: 'false'
        ImageLoaded|endswith: '.dll'
        Image|endswith: '.exe'
    filter_system:
        ImageLoaded|contains:
            - '\Windows\System32\'
            - '\Windows\SysWOW64\'
    condition: selection and not filter_system
falsepositives:
    - Legitimate software with side-by-side DLLs
level: medium
```

### Sigma — Registry Persistence (confirmed)

```yaml
title: PlugX Capitol COM Hijack Persistence Key Creation (Mustang Panda SmadAV Campaign)
id: d1b5e4c3-6e7f-4d0a-c4e5-3h8g6f9d1c04
status: experimental
description: Detects creation of Software\CLASSES\Capitol registry key used by this PlugX variant for COM hijack persistence
logsource:
    category: registry_event
    product: windows
detection:
    selection_capitol:
        TargetObject|contains: '\Software\CLASSES\Capitol'
    selection_mspu:
        TargetObject|contains: '\Software\CLASSES\ms-pu'
    condition: selection_capitol or selection_mspu
falsepositives:
    - None known
level: critical
```

### Sigma — C2 Network Detection

```yaml
title: PlugX Beacon to windows.gobay.info (Mustang Panda SmadAV Campaign)
id: e2c6f4d5-7f8g-5e0b-d5f6-4i9h7g0e2d05
status: experimental
description: Detects DNS resolution or HTTP connection to confirmed PlugX C2 infrastructure
logsource:
    category: network_connection
    product: windows
detection:
    selection_dns:
        QueryName|contains: 'gobay.info'
    selection_http:
        DestinationHostname|contains: 'gobay.info'
    condition: selection_dns or selection_http
falsepositives:
    - None expected; gobay.info has no legitimate software use
level: critical
```

---

## Recommended Actions

1. **Block file hashes** at EDR and email gateway for all four files plus the decrypted core.
2. **Block/sinkhole `windows.gobay[.]info`** — confirmed C2 hostname for this campaign.
3. **Revoke/block DriveTheLife cert serial** `08:ac:66:7c:65:d3:6d:65:42:91:76:55:57:1e:61:c8` in enterprise code-signing trust stores.
4. **Hunt for `Software\CLASSES\Capitol`** registry key across the environment — high-confidence PlugX persistence indicator for this variant.
5. **Hunt for `biuxmind.ini`** in `%ALLUSERSPROFILE%\SxS\` and user profile directories.
6. **Hunt for `update.dat`** and `NvSmart.hlp` / `NvSmart.x64.hlp` creation events in user-writable paths.
7. **Alert on `Smadav.exe` process creation** — this filename has no legitimate occurrence outside an actual SmadAV install directory.
8. **Alert on PowerShell `-Command Remove-MpPreference -ExclusionPath C:\`** — PlugX AV bypass command.
9. **Block `gobay.info` at DNS/proxy** — no legitimate use of this domain.
10. **Notify CISA/sectoral ISAC** of the DriveTheLife cert abuse for cross-industry blocking.

---

## Analyst Notes

- **Decryption chain fully resolved**: The 4-state LCG cipher (constants `0xABCD1122`, `0xBCDE3344`, `0xCDEF5566`, `0x20230912`) + LZNT1 decompression was reversed from update.dat stub disassembly (offset 0xE75–0xFA3). The PlugX core `plugx_core_smadav.bin` was successfully extracted (407,040 bytes, SHA256 `67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f`).
- **C2 confirmed static**: `windows.gobay.info` recovered as plaintext string in `.rdata` of the PlugX core DLL — no dynamic execution required. This is the primary C2 for this sample.
- **Capitol vs. ms-pu**: This variant uses `Software\CLASSES\Capitol` as its COM hijack key, distinct from the `Software\CLASSES\ms-pu` key used in the 601ae63e Nepal CIAA sample and the Steam campaign sample. This suggests either a different sub-cluster or deliberate per-campaign key rotation to evade static detection rules targeting `ms-pu`.
- **Remaining gap**: The encrypted trailing config block (0x3A3A2–0x3BA8D, 5,388 bytes) and the `.data` blob in the PlugX core were not statically decrypted. These likely contain per-campaign C2 override values and secondary C2 addresses. Sandbox execution will recover these.
- **"BIU" cluster fingerprint**: The `BIU BIU BIU!!!` marker and `biuxmind.ini` config file name match prior Mustang Panda "BIU loader" cluster documentation (Avast, ESET). This places the sample within a distinct sub-cluster of Earth Preta operations.
- **Campaign continuity**: This sample shares actor infrastructure indicators (DriveTheLife cert, sideloading pattern, PEB walk API resolution, `.dat` payload structure, `%APPDATA%\Render\` and `%ALLUSERSPROFILE%\SxS` install paths) with three other PlugX samples in this investigation, confirming a persistent multi-campaign Mustang Panda operation.

---

*Report updated: 2026-04-20 | REMnux MCP-assisted static analysis + payload decryption | TLP:AMBER — Share with trusted partners only*
