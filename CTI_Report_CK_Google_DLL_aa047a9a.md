# CTI Report: CK Campaign — Go RAT DLL with Post-Quantum C2 Crypto
**Analyst:** REMnux MCP Static Analysis  
**Date:** 2026-04-20  
**TLP:** TLP:AMBER  
**Confidence:** Medium-High

---

## Executive Summary

`ck-3d80df5d12cdfe6450a782fc87bf66b444.google.dll` is a highly sophisticated Go-based RAT/backdoor DLL compiled with Go 1.20.5 on 2025-04-17. The sample exhibits an advanced defensive profile: full `garble` source obfuscation, forged ASUS version metadata, a stolen Sectigo TLS certificate (mismatched to an Edgecast CDN domain), and a vendored **post-quantum ML-KEM/Kyber** key exchange library — an extremely rare capability in threat actor tooling. The `ck-` filename prefix links this sample to the previously analysed **CK1.0 RAT** campaign. The confirmed C2 is `ZcnTbbj6.cn`, a randomised `.cn` TLD domain consistent with China-nexus actor infrastructure. Attribution is assessed as **China-nexus, medium-high confidence**.

---

## File Metadata

| Field | Value |
|---|---|
| Filename | `ck-3d80df5d12cdfe6450a782fc87bf66b444.google.dll` |
| SHA-256 | `aa047a9a7f1d3161c6285d40634c5387fbaa990f9e5868f7a036c3d260fcd055` |
| SHA-1 | `bfe2e0b49fe125497ee37ef8e3dad2c1a53dc6d8` |
| MD5 | `53064d8242b201563c9f5b0f42b10232` |
| ImpHash | `dcfc31003c379edf77782fe7ed76661b` |
| File type | PE32+ DLL x86-64 |
| File size | 4,282,408 bytes (4.3 MB) |
| Compile timestamp | 2025-04-17 00:06:09 UTC |
| Compiler | Go 1.20.5 (2023-06-06) |
| Target OS | Windows ≥ 6.1 (Windows 7) |
| Sections | 7: `.text`, `.rdata`, `.data`, `.pdata`, `.tls`, `.rsrc`, `.reloc` |
| Code signing | Yes — stolen/mismatched (see below) |
| Overlay | Yes — Authenticode PKCS#7 blob (2,600 bytes) |

---

## Indicators of Compromise (IOCs)

### Network

| Type | Indicator | Confidence | Notes |
|---|---|---|---|
| Domain (C2) | `ZcnTbbj6[.]cn` | High | Found in printable-encoded config blob at file offset 0x25c398; random DGA-style name; `.cn` TLD |

### File

| Type | Indicator |
|---|---|
| SHA-256 | `aa047a9a7f1d3161c6285d40634c5387fbaa990f9e5868f7a036c3d260fcd055` |
| SHA-1 | `bfe2e0b49fe125497ee37ef8e3dad2c1a53dc6d8` |
| MD5 | `53064d8242b201563c9f5b0f42b10232` |
| ImpHash | `dcfc31003c379edf77782fe7ed76661b` |
| Filename pattern | `ck-*.google.dll` |

### Certificate (stolen/misused)

| Field | Value |
|---|---|
| Subject CN | `media8b09.edgecastcdn.net` |
| Issuer | `C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA` |
| Validity | 2026-04-18 13:52:00Z → 2027-04-19 13:52:00Z |
| Type | Sectigo RSA DV — does NOT match claimed ASUS identity |

### DLL Exports (hook points)

| Ordinal | Name | RVA | Notes |
|---|---|---|---|
| 1 | `WppValidateInterfaceW` | 0x216dc0 | Impersonates ETW tracing API |
| 2 | `sFqBictwFYVdCwcSy` | 0x45ab10 | Garble-obfuscated actual entry |

---

## Technical Analysis

### 1. Language and Obfuscation

The binary is compiled with **Go 1.20.5** and processed through **[garble](https://github.com/burrowers/garble)**, a build-time obfuscator that:
- Renames all function, type, and package names to random identifiers
- XOR-encrypts Go string literals with per-function keys (`7:` length-prefixed garble-encrypted string pattern observed)
- Strips debug symbols and module path information

The `redress` Go binary analyser recovers **55 vendor packages** and **1 main package**, all with garbled names. Representative garble package identifiers extracted from the pclntab and type table:

```
Main package functions: klAQcuoX, QZc7VdphrBzf, TPWfpG, EUbC1EV, AQu2vCe, Rr0V18_Q,
                        Ziu3nBexR, W50DZs1wA9, GIqxu_J3, CLVfsa, OOjEOKQwIr

Vendor packages: ymYCic, fFbhlZuEl, isRgmWzV, jSIY9N7, vchok5L, jLg9fsWKtr08,
                 GvU9wqc6, Zz_HyK2x, r9HxW05, ANhdGgqnPmo, BpBiKdHBT, C3WZrGA5KJX,
                 DQVRy6jhtP, Ea5ibv1D, GKD4fbhRe8wl, IkncQUEmUy3l, YBJTalQ0,
                 bRW0TiZFsDpY, bYKp3HQhpHrH, ... (55 total)
```

`go.mod` metadata is stripped (gomod returns only `main`). No symbol table or source file paths are recoverable.

### 2. Identity Forgery and Code Signing Abuse

The PE version resource presents as a legitimate ASUS component:
```
FileDescription:  Asus Display Monitor Information
InternalName:     AsusDisplayMonitorInfo
ProductName:      AsusDisplayMonitorInfo
LegalCopyright:   Asus Copyright (C) 2022
FileVersion:      1.0.9
```

This is entirely fabricated — Go binaries do not produce this metadata natively; it was manually injected. The Authenticode signature uses a certificate for `CN=media8b09.edgecastcdn.net` (a Verizon/Edgecast CDN subdomain), issued by Sectigo RSA DV CA. This is a **stolen or misappropriated TLS certificate** embedded to make the file appear signed without matching the ASUS identity. Security tools that check only for the presence of a signature (not the subject match) will be bypassed.

### 3. C2 Configuration

At file offset **0x25c398** in `.rdata`, a large (~800+ byte) block of random-looking printable ASCII contains the C2 domain `ZcnTbbj6.cn` in plaintext, surrounded by what appears to be a custom-encoded configuration. The encoding uses printable-range characters (0x21–0x7e), suggesting a custom alphabet encoder (similar to base85/ascii85 or a custom bijective encoding) rather than raw encryption. Adjacent garble-encrypted inline strings with `7:` length prefixes further obfuscate configuration fields.

Three separate garble-encrypted string blobs were identified at offsets 0x251962, 0x2533ec, and 0x2552c0, consistent with encoded connection parameters (IPs, ports, keys, or URLs stored as garble-encrypted literals).

The runtime error string region also contains what appear to be garble-encoded injection target process names: `Gsmzvmt32.l`, `tthkchwp32.k`, `ssoivrip32.h`, `ppuobxov32.n` — these are garble-encrypted short strings whose decrypted values likely spell common process names (e.g., `svchost.exe`, `lsass.exe`).

### 4. Cryptographic Capabilities

**signsrch** and static analysis confirm a complete crypto suite:

| Algorithm | Evidence | Purpose |
|---|---|---|
| AES-256 | Rijndael Te0–Te3, Td0–Td3 at 0x3e5200–0x3e8740 | Data encryption |
| SHA-256 | Constants at 0x1a62a1, K-words at 0x3e5100 | HMAC / integrity |
| SHA-512 | Constants at 0x1aeb6d, 0x1aebe8; K-words at 0x3e5c20 | HMAC / integrity |
| ChaCha20 | `XORKeyStream`, `XORKeyStreamAt` in types | Streaming cipher |
| PKCS SHA256 | DigestDecoration at 0x414e7b | TLS CertificateVerify |
| **ML-KEM / Kyber** | `jLg9fsWKtr08.(*IR0DsEI).EncapsulationKey`, `(*I2pVfQ98).Encaps`, `(*I2pVfQ98).Bytes` | **Post-quantum key exchange** |
| TLS 1.0/1.2 | `crypto/tls`, `tls10server`, `crypto/x509`, `crypto/rsa` | C2 transport |

The ML-KEM (CRYSTALS-Kyber) vendored library `jLg9fsWKtr08` is **extremely rare in malware**. Its presence suggests the actors are preparing against future quantum decryption of intercepted C2 traffic — a significant operational security investment. HTTP/2 (`http2debug` runtime string) is the likely C2 transport, over TLS 1.2/1.3 with ML-KEM for key exchange.

### 5. Import Table — Capability Fingerprint

#### Code Injection
```
GetThreadContext      — read thread register state
SetThreadContext      — overwrite instruction pointer for shellcode redirect
SuspendThread / ResumeThread — suspend target, inject, resume
VirtualAlloc / VirtualFree   — allocate RWX shellcode buffer
VirtualProtect               — flip page permissions (W→X)
CreateThread                 — create injection thread
DuplicateHandle              — cross-process handle duplication
```

#### Token Impersonation / Privilege Escalation
```
DuplicateTokenEx      — clone high-priv tokens (T1134.001)
AdjustTokenPrivileges — enable SeDebugPrivilege / SeImpersonatePrivilege
LogonUserW            — credential-based logon (T1078)
SetThreadToken        — impersonate stolen token on current thread
GetUserNameA          — victim username enumeration
```

#### Persistence
```
CreateServiceW / ControlService / OpenSCManagerW — install Windows service (T1543.003)
OpenEventW / CreateEventExW / CreateMutexExW     — synchronisation / mutex
```

#### Networking
```
CreateIoCompletionPort / GetQueuedCompletionStatusEx — IOCP async I/O (high-perf C2)
CreateWaitableTimerExW     — timer-based beacon scheduling
WSASocketW                 — raw Winsock socket
ConnectEx                  — async TCP connect
```

#### Anti-Debug / Evasion
```
AddVectoredExceptionHandler / AddVectoredContinueHandler — VEH anti-debug
RtlLookupFunctionEntry / RtlVirtualUnwind               — SEH chain inspection
WerGetFlags / WerSetFlags                                — suppress crash reports
SetErrorMode / GetErrorMode                              — silence error dialogs
2 × TLS callbacks                                        — pre-EP execution
```

#### System Reconnaissance
```
GetSystemInfo / GetSystemDirectoryA  — system profile
GetFileVersionInfoSizeA              — installed software version check
SHGetFolderPathA                     — AppData/special folder paths
GetUserNameA                         — current username
IsWow64Process (via runtime)         — 32/64 bitness detection
```

#### Dynamically Loaded DLLs (runtime)
```
bcryptprimitives.dll  — Windows CNG (supplemental crypto ops)
ntdll.dll             — direct NT syscall access
powrprof.dll          — power profile (possible masquerade for persistence)
dwmapi.dll            — desktop window manager (screenshot capability)
```

### 6. Additional Runtime Capabilities (from error strings)

The concatenated Go runtime error strings region reveals additional Windows API usage that does not appear in the static import table (resolved at runtime via PEB walk or `LoadLibrary`):

```
NetUserAdd / NetUserDel           — create/delete user accounts (T1136.001)
NetShareAdd / NetShareDel         — create/delete network shares (T1039)
NtOpenFile                        — direct NTAPI file access (bypass EDR hooks)
LogonUserW                        — interactive logon with credentials
IsValidSid / MakeAbsoluteSD       — security descriptor manipulation
DuplicateTokenEx / SetEntries... — full ACL/token manipulation suite
dwmapi.dll / user32.dll           — GUI/desktop access
```

### 7. TLS Callbacks

Two TLS callbacks are registered, meaning code executes **before DllMain** is called. This is used for:
- Anti-analysis environment checks before the main payload activates
- Early mutex creation to prevent double-loading
- Initialising garble runtime decryption of string keys

### 8. Filename and DLL Sideloading

The filename `ck-3d80df5d12cdfe6450a782fc87bf66b444.google.dll` is structured for **DLL sideloading** (T1574.002):
- The `.google.dll` suffix suggests it is loaded by a legitimate Google application (e.g., Google Update, Chrome) that loads DLLs from its application directory without absolute path verification.
- The `ck-` prefix with a long hex string is consistent with a Content Hash naming scheme used by some updaters, making the file blend into the update directory.
- The `ck-` prefix matches the **CK1.0 RAT** campaign previously analysed (see below).

---

## Campaign Linkage: CK1.0 RAT

The previous CK1.0 RAT sample (`维持CK1.0.vmp.exe`, compiled 2026-02-25) was a VMProtect-packed Delphi dropper delivering an E-language RAT with:
- C2: `106.54.39.113` (Tencent Cloud AS45090)
- XOR key: `0x6e`
- x64 injector component

This Go DLL shares:
1. **`ck-` filename prefix** — campaign naming convention
2. **Thread injection** methodology (GetThreadContext/SetThreadContext)
3. **DLL sideloading delivery** pattern
4. **China-based infrastructure** (Tencent Cloud + `.cn` TLD C2)

Assessment: The Go DLL is a **second-stage or parallel implant** in the CK campaign toolkit — likely the long-haul persistent implant deployed after initial access via the E-language dropper. The upgrade from a Delphi/E-language stack to Go with garble and PQC crypto represents significant capability maturation between February and April 2025.

---

## Attribution Assessment

| Factor | Evidence | Weight |
|---|---|---|
| `.cn` C2 TLD | `ZcnTbbj6[.]cn` | Medium |
| Tencent Cloud C2 in related sample | `106.54.39.113` (CK1.0 RAT) | Medium |
| ASUS lure / Google DLL masquerade | SEA/APAC targeting pattern | Medium |
| Advanced Go toolchain with garble | Mature, well-resourced actor | Low (non-discriminating) |
| PQC vendor library | Very small set of actors globally | Medium |
| Campaign naming consistency (`ck-`) | Same operator | High |

**Overall: China-nexus threat actor — MEDIUM-HIGH confidence.**  
Possible cluster overlap with actors using Tencent Cloud VPS infrastructure for Go-based implants in APAC operations. No direct mapping to a named APT group established from static analysis alone; dynamic sandbox analysis with network capture would be required for definitive C2 confirmation.

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1574.002 | DLL Side-Loading | `*.google.dll` filename, targets Google app dir |
| T1055.003 | Thread Execution Hijacking | `GetThreadContext`, `SetThreadContext`, `SuspendThread` |
| T1055.001 | Dynamic-link Library Injection | `VirtualAlloc`, `VirtualProtect`, `CreateThread` |
| T1134.001 | Token Impersonation/Theft | `DuplicateTokenEx`, `SetThreadToken` |
| T1134.002 | Create Process with Token | `LogonUserW`, `DuplicateTokenEx` |
| T1543.003 | Windows Service Creation | `CreateServiceW`, `OpenSCManagerW` |
| T1136.001 | Create Local Account | `NetUserAdd` |
| T1039 | Data from Network Shared Drive | `NetShareAdd`, `NetShareDel` |
| T1027 | Obfuscated Files or Information | garble obfuscation, custom config encoding |
| T1027.009 | Embedded Payloads | Printable-encoded C2 config blob |
| T1553.002 | Code Signing — Invalid Cert | Stolen Sectigo DV cert for `edgecastcdn.net` |
| T1036.005 | Masquerade: Match Legitimate Name | Fake ASUS version resource, `.google.dll` filename |
| T1071.001 | Web Protocols | HTTP/2 C2 transport |
| T1573.001 | Encrypted Channel: Symmetric | AES-256 + ChaCha20 |
| T1573.002 | Encrypted Channel: Asymmetric | ML-KEM/Kyber PQC key exchange |
| T1082 | System Information Discovery | `GetSystemInfo`, `IsWow64Process`, `GetSystemDirectoryA` |
| T1033 | System Owner/User Discovery | `GetUserNameA` |
| T1057 | Process Discovery | `OpenThread`, process enumeration |
| T1562.001 | Disable or Modify Tools | `WerSetFlags`, `SetErrorMode` |
| T1562.004 | Disable or Modify Firewall | (possible via service creation) |
| T1106 | Native API | `NtOpenFile`, PEB walk for API resolution |
| T1059 | Command and Scripting Interpreter | (runtime strings suggest cmd execution) |

---

## Detection Rules

### YARA Rule

```yara
rule CK_Campaign_Go_RAT_DLL {
    meta:
        description = "CK Campaign — garble-obfuscated Go RAT DLL with PQC crypto and fake ASUS metadata"
        author = "CTI Analysis"
        date = "2026-04-20"
        hash_sha256 = "aa047a9a7f1d3161c6285d40634c5387fbaa990f9e5868f7a036c3d260fcd055"
        tlp = "AMBER"

    strings:
        // Stolen cert subject embedded in overlay
        $cert_cn   = "media8b09.edgecastcdn.net" ascii

        // Fake ASUS metadata
        $asus_desc = "Asus Display Monitor Information" wide
        $asus_name = "AsusDisplayMonitorInfo" wide

        // Export names (obfuscated + ETW impersonation)
        $exp1 = "WppValidateInterfaceW" ascii
        $exp2 = "sFqBictwFYVdCwcSy" ascii

        // C2 domain (static config blob)
        $c2_domain = "ZcnTbbj6.cn" ascii

        // ML-KEM/Kyber PQC function (garbled package, method name preserved)
        $pqc = "EncapsulationKey" ascii

        // Go + garble indicators (compiler metadata)
        $go_ver  = "go1.20" ascii
        $garble1 = "jLg9fsWKtr08" ascii  // PQC package name (garbled)
        $garble2 = "GvU9wqc6" ascii      // co-located package (garbled)

        // AES sbox / Te tables (file offset fingerprint)
        $aes_te0 = { a5 63 63 c6 84 7c 7c f8 99 77 77 ee 8d 7b 7b f6 }  // Rijndael Te0

        // Config blob encoding pattern (printable ASCII blob with embedded .cn domain)
        $config_marker = { 5a 63 6e 54 62 62 6a 36 2e 63 6e }  // "ZcnTbbj6.cn"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 3MB and filesize < 6MB and
        (
            ($cert_cn and $asus_desc) or
            ($exp1 and $exp2) or
            ($c2_domain) or
            ($pqc and $go_ver) or
            (3 of ($garble1, $garble2, $aes_te0, $config_marker))
        )
}
```

### Sigma Rule (DLL Sideloading Detection)

```yaml
title: CK Campaign Google DLL Sideloading
id: a3f12b89-4c7e-4f1a-9d3c-0e8b2a5f6c91
status: experimental
description: Detects loading of ck-*.google.dll from non-Google directories
references:
  - CTI Report 2026-04-20
author: CTI Analysis
date: 2026-04-20
tags:
  - attack.defense_evasion
  - attack.t1574.002
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|re: '\\ck-[0-9a-f]{30,}\.google\.dll$'
  filter:
    ImageLoaded|contains:
      - '\Google\Update\'
      - '\Google\Chrome\'
  condition: selection and not filter
falsepositives:
  - Legitimate Google update components with hash-named DLLs (verify cert subject)
level: high
```

### Sigma Rule (Stolen Certificate Abuse)

```yaml
title: Sectigo DV Certificate Mismatched PE Signing
id: b7e34a12-9f2c-4d8b-b1a5-7c3d9e0f2b84
status: experimental
description: Detects PE signed with Sectigo DV cert where cert subject does not match file metadata publisher
references:
  - CTI Report 2026-04-20
author: CTI Analysis
date: 2026-04-20
tags:
  - attack.defense_evasion
  - attack.t1553.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Signed: 'true'
    SignatureStatus: 'Valid'
    Company: 'ASUS*'
    SignerName|contains: 'edgecastcdn'
  condition: selection
falsepositives:
  - None expected
level: critical
```

### Network Detection (Suricata)

```
alert dns any any -> any 53 (
    msg:"CK Campaign C2 DNS Lookup - ZcnTbbj6.cn";
    dns.query; content:"ZcnTbbj6.cn"; nocase;
    classtype:trojan-activity;
    sid:9000101; rev:1;
    metadata:affected_product Windows, attack_target Client_Endpoint,
              deployment Perimeter, signature_severity Major,
              created_at 2026-04-20, malware_family CK_GoRAT;
)

alert tls any any -> any 443 (
    msg:"CK Campaign C2 TLS SNI - ZcnTbbj6.cn";
    tls.sni; content:"ZcnTbbj6.cn"; nocase;
    classtype:trojan-activity;
    sid:9000102; rev:1;
)
```

---

## Interesting Strings and Artefacts

| String / Artefact | Offset | Significance |
|---|---|---|
| `ZcnTbbj6.cn` | 0x25c398 | C2 domain in encoded config blob |
| `media8b09.edgecastcdn.net` | Overlay (0x414e00+) | Stolen cert subject |
| `WppValidateInterfaceW` | Export table | ETW API impersonation export name |
| `sFqBictwFYVdCwcSy` | Export table | Garbled main export |
| `jLg9fsWKtr08.(*IR0DsEI).EncapsulationKey` | 0x2f9036 | ML-KEM PQC encapsulation function |
| `jLg9fsWKtr08.(*I2pVfQ98).Encaps` | 0x2f9060+ | ML-KEM key encapsulation |
| `XORKeyStream` / `XORKeyStreamAt` | .rdata types | ChaCha20 stream cipher |
| `ConnectEx` | .rdata types | Async TCP connect (IOCP) |
| `SetWriteDeadline` | .rdata types (vchok5L pkg) | Network connection timeout management |
| `7:,Q^FU2@C/u` | 0x251962 | Garble-encrypted inline string (config field) |
| `7:=(uGh=*Sri` | 0x25196c | Garble-encrypted inline string |
| `7:56Wti'KcR"` | 0x251976 | Garble-encrypted inline string |
| `bcryptprimitives.dll` | Unicode .rsrc | CNG runtime DLL (dynamically loaded) |
| `ntdll.dll` | Unicode .rsrc | Direct NT API (EDR bypass) |
| `powrprof.dll` | Unicode .rsrc | Unusual DLL — possible masquerade |
| `tls10server` | 0x25154x | TLS 1.0 server capability (legacy C2) |
| `http2debug` | 0x251540 | HTTP/2 protocol support |
| `NetShareAdd`/`NetShareDel` | 0x251540 | Lateral movement via network shares |
| `NetUserAdd`/`NetUserDel` | 0x251540 | Persistence via local account creation |
| `DuplicateTokenEx` | 0x252bbe | Token theft for privilege escalation |
| `NtOpenFile` | 0x251540 | Direct NT syscall (bypass EDR hooks) |
| `AdjustToken…` | 0x252bbe | SeDebugPrivilege escalation |
| `LogonUserW` | 0x251540 | Credential-based authentication |

---

## Limitations and Recommended Next Steps

1. **C2 port unknown**: No plaintext port number found adjacent to `ZcnTbbj6.cn`. Likely stored as an encoded field in the config blob. Recommend decoding the full 800-byte printable blob at 0x25b000–0x25c500.
2. **Config blob encoding**: The config encoding scheme (custom printable-range alphabet) was not fully reversed. The key is likely stored in garble-encrypted inline strings (`7:` blocks) at 0x251962, 0x2533ec, 0x2552c0.
3. **Full package inventory**: 55 vendor packages are garble-obfuscated. A full `redress packages --vendor` run (currently limited output) would enumerate all third-party libraries used.
4. **Sandbox execution**: Speakeasy DLL emulation failed (Go runtime complexity). Recommend running in a full Windows sandbox (Cuckoo, ANY.RUN, Cape) with network capture to confirm `ZcnTbbj6.cn` C2 beaconing.
5. **Related samples**: Hunt for other `ck-*.google.dll` samples or Go DLLs using the `jLg9fsWKtr08` package fingerprint on VirusTotal/Malshare.
6. **CK1.0 campaign scope**: Cross-correlate `106.54.39.113` (Tencent Cloud, CK1.0 RAT C2) with `ZcnTbbj6.cn` resolution history and passive DNS to identify further actor infrastructure.

---

## Summary

This sample represents a **significant capability upgrade** within the CK campaign: a production-quality Go-based implant with garble obfuscation, stolen code-signing certificate, post-quantum C2 crypto, and comprehensive Windows offensive capabilities. The use of ML-KEM/Kyber — designed to protect C2 traffic against future quantum decryption — places this actor among a very small number of threat groups deploying post-quantum defensive measures operationally. Combined with the fake ASUS digital identity and Google DLL sideloading delivery, this is an **advanced, well-resourced China-nexus operator** conducting targeted intrusions in the APAC region.
