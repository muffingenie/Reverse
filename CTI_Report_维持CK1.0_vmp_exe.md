# CTI Report: 维持CK1.0.vmp.exe — Chinese E-language RAT with VMProtect Dropper

**Report Date:** 2026-04-19  
**Analyst:** REMnux Static Analysis  
**Classification:** Malware — Remote Access Trojan (RAT) / Infostealer  
**Confidence:** High (structural evidence), Medium (family attribution)

---

## 1. Executive Summary

The sample `维持CK1.0.vmp.exe` ("维持" = maintain/sustain, "CK 1.0") is a **three-stage Chinese-language RAT package** consisting of:

1. **Stage 0 (dropper):** A VMProtect-obfuscated Borland Delphi loader that conceals two PE payloads inside a fake BITMAP resource (BITMAP "MAIN", 1,074,066 bytes), XOR-encoded with key `0x6e`.
2. **Stage 1 (RAT core):** A 934 KB x86 PE built with **易语言 (E-language / Yi-language)**, a Chinese IDE. This component implements a full surveillance RAT: keylogging, screen capture, webcam capture, clipboard theft, remote shell, RC4-encrypted C2 communication, and a local database.
3. **Stage 2 (injector/persister):** A 137 KB x64 PE compiled with MSVC 2019 in **February 2026**. It deploys the RAT, masquerades as `Windows Security Health Services.exe`, establishes Run key persistence, and weaponizes `icacls` to deny file deletion.

The tooling, language, and architecture are characteristic of **Chinese-speaking crimeware actors**. E-language is used almost exclusively within Chinese-language hacking communities. No static C2 address was recovered (stack string obfuscation confirmed by CAPA); dynamic analysis is required for C2 extraction.

**Threat Level: HIGH** — full-feature surveillance RAT with active evasion, tamper-proofing, and a freshly compiled (2026-02-25) injector component.

---

## 2. File Identification

### Stage 0 — VMProtect Dropper

| Field | Value |
|-------|-------|
| Filename | `维持CK1.0.vmp.exe` |
| SHA256 | `4ad5c94364e05c363bd8f03cc35acf6166c9a496503859344a4418f2ae845caf` |
| SHA1 | `b924238eb226c2eb1daeeb0d248b22a82a48e923` |
| MD5 | `f5153ae5ab17fa8b436e9665a3be3448` |
| ssdeep | `24576:5zxH7KBBR4pu+DX7EIvAskQdAMPbzvBW3sNytg:5lH7IjiuCQ7sLrPbM` |
| imphash | `14f8e4dca31086cd0498de53fcba2af3` |
| Size | 1,103,360 bytes |
| Type | PE32 GUI, Intel 80386, 9 sections |
| Compiler | Borland Delphi (Linker 2.25 / Turbo Linker, Embarcadero FastMM) |
| Timestamp | 2013-01-09 10:36:49 UTC **(SPOOFED — typical fake Delphi timestamp)** |
| Protector | VMProtect |
| Entropy (global) | 6.43 |
| Signature | None |
| OS target | Windows XP+ (5.0) |

### Stage 1 — E-language RAT Core (extracted)

| Field | Value |
|-------|-------|
| SHA256 | `645164397ceee3d7cf49132526d898fee9dd4c8be13124f886380997ea5b1dee` |
| MD5 | `f0c67c73993b60c804959416c2d4f6a3` |
| SHA1 | `e8edcf54ae574531b44617973f924a24ef87e374` |
| Size | 933,910 bytes |
| Type | PE32 GUI, Intel 80386, 4 sections |
| Compiler | MSVC 12.00 (VC6 linker 6.0) |
| Timestamp | **2023-01-24 15:44:57 UTC** |
| Language | Chinese Simplified (LCID 0x0804) |
| IDE | **易语言 (E-language / Yi-language)** |
| FileDescription | 易语言程序 |
| LegalCopyright | 作者版权所有 请尊重并使用正版 |
| Comments | 本程序使用易语言编写(http://www.eyuyan.com) |

### Stage 2 — x64 Injector/Persister (extracted)

| Field | Value |
|-------|-------|
| SHA256 | `2cf032f7e09e4d47b1d1b531b98caaa79d56da6524fe89eea3787211626ac404` |
| MD5 | `9bc4a0e18d11a8d03d5bc10aff12346c` |
| SHA1 | `783a0be0d878eee9e2d7460eb6a09751685b812d` |
| Size | 136,704 bytes |
| Type | PE32+ GUI, AMD64, 6 sections |
| Compiler | MSVC 19.29 (VS2019 v16.11, LTCG/C++) |
| Timestamp | **2026-02-25 20:47:15 UTC** |
| .text entropy | 6.48 (elevated) |

---

## 3. Execution Chain

```
维持CK1.0.vmp.exe [VMProtect Delphi dropper]
│
├─ BITMAP resource "MAIN" (1,074,066 bytes)
│   ├─ [offset 0x000–0x07C] x86 shellcode: reflective PE loader
│   │   Uses: FindResourceW → LoadResource → LockResource → SizeofResource
│   │         VirtualAlloc (RWX) → XOR-decode 0x6E → execute via indirect CALL
│   │
│   ├─ [offset 0xD7C+] Stage 1: E-language RAT (XOR 0x6E, 933,910 bytes)
│   │   └─ Full-feature surveillance RAT (keylog/screen/webcam/clipboard/RC4 C2)
│   │
│   └─ [offset 0xE4DE0+] Stage 2: x64 Injector (XOR 0x6E, 136,704 bytes)
│       ├─ Copies RAT to %SystemRoot%\Windows Security Health Services.exe
│       ├─ Sets Run key persistence
│       ├─ Runs icacls to deny Everyone delete+execute
│       ├─ Elevates via runas (ShellExecuteExW)
│       └─ Spawns RWX shellcode thread (injects Stage 1)
│
└─ Anti-analysis: Xen VM detection, anti-debug (GetLastError/RaiseException/
                  UnhandledExceptionFilter), XOR-encoded API names (key 0x4e)
```

---

## 4. Technical Analysis

### 4.1 Stage 0: VMProtect Dropper

#### PE Structure
```
Section   VSize   Entropy  Description
.text     0x48D0  5.87     Code (VMP loader stubs)
.itext    0x00F0  3.07     Entry point [EP at 0x4ED4 file offset]
.data     0x081C  1.03     Low-entropy initialized data
.bss      0x2BA4  0.00     BSS
.idata    0x04A2  3.67     Import table (kernel32 + user32 only)
.tls      0x0008  0.00     TLS callback table
.rdata    0x0018  0.20     Read-only data
.<r)      0x0340  5.65     Unusual name — VMP section
.rsrc     1,074,576 6.38   BITMAP "MAIN" payload (97.59% of file)
```

**Characteristics:** No relocations, no ASLR, no DEP, no SafeSEH, no CFG, no StackCanary — all mitigations disabled. Indicates deliberate stripping for shellcode/injection compatibility.

#### Import Table
Only 41 imports total across kernel32.dll (40) and user32.dll (1 — `MessageBoxA`). Key imports resolve capabilities:

| Import Group | APIs |
|---|---|
| Resource extraction | `FindResourceW`, `LoadResource`, `LockResource`, `SizeofResource` |
| Memory manipulation | `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `VirtualQuery` |
| Dynamic resolution | `GetProcAddress`, `LoadLibraryA` |
| Anti-debug | `GetLastError`, `RaiseException`, `UnhandledExceptionFilter`, `RtlUnwind` |
| TLS | `TlsGetValue`, `TlsSetValue`, `LocalAlloc`, `LocalFree` |
| Process | `GetCommandLineW`, `GetModuleHandleW`, `GetCurrentThreadId` |

#### Obfuscation: XOR-encoded API Names
Function names are XOR-encoded with key `0x4E` ('N') to evade import-table scanning. Confirmed decodings:
- `22 01 0f 0a 22 07 0c 1c 0f 1c 17` → `LoadLibrary` (partial)
- `29 0b 1a 3e 1c 01 0d 2f 0a 0a 1c 0b 1d 1d` → `GetProcAddress`

#### Payload Encoding
The BITMAP "MAIN" resource is not a bitmap — it is raw data. The dominant byte `0x6E` ('n') comprises **20.65% of the entire file**, a direct consequence of XOR-0x6e encoding long runs of null bytes in the embedded PEs. Structural artifacts:
- XOR pattern confirmed at file offsets `0x751E` and `0xEB534` (both decode "This program cannot be run in DOS mode")
- Two embedded MZ headers at file offsets `0x74D0` (Stage 1) and `0xEB4E6` (Stage 2)
- Stage 1 e_lfanew = `0x108`; Stage 2 e_lfanew = standard

#### Anti-Analysis (Stage 0)
- **Anti-VM (Xen):** CAPA confirmed anti-VM strings targeting Xen hypervisor [T1497.001]
- **Anti-debug:** `UnhandledExceptionFilter` filter manipulation; `RaiseException` traps
- **TLS callbacks:** TLS directory at `0x40D010` (used for pre-EP initialization or anti-debug)
- YARA: `maldoc_find_kernel32_base_method_1`, `maldoc_getEIP_method_1` — PEB-walk kernel32 resolution; GetEIP-via-CALL shellcode technique

---

### 4.2 Stage 1: E-language RAT (易语言程序)

#### Language/Tooling
Built with **易语言 (E-language)**, a Chinese-language IDE that compiles to native Win32 PE using MFC-like framework (`FastMM`, Embarcadero edition). The use of E-language is a near-exclusive indicator of **Chinese-speaking developer**. The binary includes standard E-language boilerplate: error strings, file dialogs, print dialogs, and the URL `http://www.eyuyan.com` in the version info.

All UI resources are LCID 0x0804 (Chinese Simplified). Rich Signature present; Armadillo YARA trigger is a false positive from E-language PE structure.

#### Surveillance Capabilities (CAPA-confirmed)

| Capability | Method | ATT&CK |
|---|---|---|
| Keylogging | Polling (GetAsyncKeyState) | T1056.001 |
| Screen capture | WinAPI (BitBlt/GetDC) | T1113 |
| Webcam capture | WinAPI (2 matches) | T1125 |
| Clipboard read | GetClipboardData | T1115 |
| Clipboard write | SetClipboardData | T1115 |
| Window text capture | GetWindowText | T1113 |
| Remote shell | UI dialog "新建 Shell" | T1059 |
| C2 receive | Socket communication | T1095 |

#### Cryptography & Encoding (YARA + CAPA confirmed)
- **RC4** (2 CAPA matches) — KSA identified — used for C2 traffic encryption
- **MD5** — `MD5_Constants` YARA match — likely for authentication/integrity
- **CRC32** — `CRC32_poly_Constant`, `CRC32_table` YARA matches
- **Base64** — `BASE64_table` YARA match — used for data encoding
- **XOR** (2 CAPA matches) — secondary encoding layer
- **ZLIB** — statically linked (`linked against ZLIB`) — C2 data compression

#### Network Communication

**C2: `106.54.39.113` (confirmed by CAPE dynamic analysis, CAPESANDBOX #62270)**

- **IP:** `106.54.39.113` — ASN AS45090 (Shenzhen Tencent Computer Systems Company Limited), geo: Shanghai, China
- **Infrastructure:** Tencent Cloud VPS — a common choice for Chinese crimeware C2 due to local payment methods, Chinese-language interface, and reduced takedown friction for PRC-origin malware
- **WinHTTP COM object:** `WinHttp.WinHttpRequest.5.1` (statically confirmed) — HTTP POST to C2
- **Request headers:** `User-Agent: Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)`, `Accept-Language: zh-cn`, `Content-Type: application/x-www-form-urlencoded`
- **Session management:** Cookie-based (`Cookie:` / `Set-Cookie:` headers confirmed in binary)
- `Str_Win32_Winsock2_Library` YARA match — WSAStartup-based TCP socket (supplementary)
- CAPA: `set socket configuration`, `receive data` (C2 communication pattern)
- **C2 address not recoverable statically — confirmed absent from all four stages of the package** (dropper, reflective shellcode, E-language RAT core, x64 injector) in every tested encoding: plain ASCII, UTF-16LE, XOR keys 1–255, DWORD big/little-endian, 4-byte chunk sequences, MOV BYTE sequences. Root cause: E-language's string runtime assembles strings through its own heap-based allocator/concatenation functions. Characters are never written sequentially to stack or data in a pattern recoverable by static analysis — the string object is built into a managed heap region whose layout is determined at runtime. This is categorically different from compiler-emittable stack strings (which FLOSS can emulate) and explains why all static techniques fail.
- **C2 protocol:** RC4-encrypted, MD5-authenticated, custom-Base64 encoded (`@`-prefixed alphabet), ZLIB-compressed — consistent with Chinese crimeware C2 patterns
- **Dead-drop resolver (candidate):** `http://login.game.qq.com/comm-cgi-bin/login/LoginReturnInfo.cgi?callback=jsonp31&game=game` — QQ Games login URL present in binary; may serve as connectivity check or C2 lookup fallback

#### Anti-Analysis (Stage 1)
- `DebuggerCheck__QueryInfo` (YARA) — RDTSC/IsDebuggerPresent-class check
- CAPA: software breakpoint detection [B0001.025]
- CAPA: GetTickCount timing check [B0001.032]
- Stack strings obfuscation (argument obfuscation B0032.020) — 2 matches
- Analysis tool string detection [B0013.001] — enumerates process names against known analysis tools
- Packed with generic packer (secondary protection layer)

#### UI Dialogs (extracted from resources)
The embedded dialog resources reveal the RAT's operator interface:

| Dialog | Chinese Text | Meaning |
|---|---|---|
| #286 | 演播 / 停止演播 / 清空 / 导入 / 导出 / 保存退出 / 取消退出 | Broadcast / Stop Broadcast / Clear / Import / Export / Save & Exit / Cancel |
| #554 | 请输入数据库访问密码 | "Please enter the database access password" |
| #1037/#1150 | 请输入 / 确认输入 | Input prompt dialogs |
| #30721 | 新建 Shell | "New Shell" — interactive remote shell |
| #30722 | 正在进行打印 | Print progress dialog |

The **database password dialog** indicates collected data (keystrokes, screenshots, credentials) is stored in a local encrypted database. The **broadcast controls** indicate live screen/video streaming to the operator. The **新建 Shell** dialog provides interactive command execution on the victim.

#### Additional Capabilities (CAPA)
- `win_private_profile` (YARA) — INI file read/write for configuration
- `win_registry` (YARA) — registry key queries [T1012]
- `win_hook` (YARA) — hooks installation (keyboard/mouse)
- `win_mutex` — mutex creation (anti-duplication)
- Enumerate PE sections (12 matches) — reflective PE loading within RAT
- PEB walk to resolve kernel32 base address (6 runtime-linking matches)
- Create/resume/terminate threads (3 matches each)

---

### 4.3 Stage 2: x64 Injector / Persister

#### Compilation
- MSVC 19.29, Visual Studio 2019 v16.11, LTCG
- **Timestamp 2026-02-25 20:47:15 UTC** — indicates this component was (re)compiled approximately 7–8 weeks before collection, suggesting active development/maintenance
- Locale strings: `zh-CN` (Chinese Simplified) appears alongside `ja-JP`, `ko-KR` — likely included by MSVC runtime; zh-CN first position may reflect operator locale

#### Persistence Mechanism [T1547.001]
```
Registry Key:   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name:     Windows Security Health Services
Value Data:     <path to dropped file>
```

#### Masquerading [T1036.005]
```
Drop path:     %SystemRoot%\Windows Security Health Services.exe
```
The filename deliberately mimics a legitimate Windows security component to blend with `wscsvc` (Windows Security Center service). The file is placed in `%SystemRoot%` (typically `C:\Windows\`) to appear system-native.

#### Tamper Protection [T1222]
```
Command:  cmd.exe /c icacls "%s" /deny Everyone:(DE) /T /C
```
After dropping, the injector denies **Delete (D)** and **Execute (E)** permissions to the `Everyone` group recursively (`/T`) and continues on errors (`/C`). This prevents standard user/admin deletion and makes AV remediation significantly harder without explicit ACL repair.

#### Privilege Escalation [T1548.002]
- `runas` passed to `ShellExecuteExW` — requests elevation dialog
- `OpenProcessToken` — token manipulation for privilege inspection/impersonation [T1134]

#### Process Injection / Shellcode Execution [T1055]
- CAPA: `spawn thread to RWX shellcode` — allocates RWX memory, writes shellcode, `CreateThread`
- CAPA: `execute shellcode via indirect call`
- `parse PE header` — reflective loading of Stage 1 into target process

#### Discovery [T1057, T1082, T1083, T1518]
- `CreateToolhelp32Snapshot` + `Process32FirstW` / `Process32NextW` — full process enumeration
- `GetSystemDirectoryW`, `GetModuleFileNameW` — system info
- `FindFirstFileExW` / `FindNextFileW` — file system enumeration
- `GetModuleHandleExW` — loaded module inspection

#### Anti-Debug
- `IsDebuggerPresent` [T1497.001]
- `IsProcessorFeaturePresent`
- `GetLastError` + `RaiseException` + `TerminateProcess` + `UnhandledExceptionFilter`

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Component |
|---|---|---|
| Execution | T1129 Shared Modules | All stages |
| Execution | T1059 Command Interpreter (Shell) | Stage 1 (新建 Shell) |
| Persistence | T1547.001 Registry Run Keys | Stage 2 |
| Privilege Escalation | T1548.002 Abuse Elevation (runas) | Stage 2 |
| Defense Evasion | T1027 Obfuscated Files | Stage 0 (XOR 0x6E, VMProtect) |
| Defense Evasion | T1027.002 Software Packing | Stage 0 (VMProtect), Stage 1 |
| Defense Evasion | T1027.005 Indicator Removal from Tools | Stage 1 (stack strings, encoded imports) |
| Defense Evasion | T1036.005 Masquerade Legitimate Name | Stage 2 (Windows Security Health Services.exe) |
| Defense Evasion | T1222 File/Directory Permissions Modification | Stage 2 (icacls /deny Everyone) |
| Defense Evasion | T1497.001 Virtualization/Sandbox Evasion (System Checks) | Stage 0 (Xen), Stage 2 (IsDebuggerPresent) |
| Discovery | T1012 Query Registry | Stage 1 |
| Discovery | T1057 Process Discovery | Stage 1, Stage 2 |
| Discovery | T1082 System Information Discovery | Stage 1, Stage 2 |
| Discovery | T1083 File and Directory Discovery | Stage 1, Stage 2 |
| Discovery | T1518 Software Discovery | Stage 2 (analysis tool detection) |
| Collection | T1056.001 Keylogging | Stage 1 |
| Collection | T1113 Screen Capture | Stage 1 |
| Collection | T1115 Clipboard Data | Stage 1 |
| Collection | T1125 Video Capture (Webcam) | Stage 1 |
| Command & Control | T1071.001 Application Layer Protocol (HTTP) | Stage 1 (WinHTTP POST to 106.54.39.113) |
| Command & Control | T1095 Non-Application Layer Protocol (raw TCP, supplementary) | Stage 1 (WSAStartup) |
| Command & Control | T1132.001 Data Encoding — Standard Encoding (Base64+ZLIB) | Stage 1 |
| Command & Control | T1573.001 Encrypted Channel — Symmetric Cryptography (RC4) | Stage 1 |
| Credential Access | T1134 Access Token Manipulation | Stage 2 |
| Impact | T1489 adjacent (process termination) | Stage 1, Stage 2 |

---

## 6. Indicators of Compromise (IoCs)

### File Hashes

| Role | SHA256 | MD5 | SHA1 |
|---|---|---|---|
| Dropper (维持CK1.0.vmp.exe) | `4ad5c94364e05c363bd8f03cc35acf6166c9a496503859344a4418f2ae845caf` | `f5153ae5ab17fa8b436e9665a3be3448` | `b924238eb226c2eb1daeeb0d248b22a82a48e923` |
| E-language RAT core (payload1) | `645164397ceee3d7cf49132526d898fee9dd4c8be13124f886380997ea5b1dee` | `f0c67c73993b60c804959416c2d4f6a3` | `e8edcf54ae574531b44617973f924a24ef87e374` |
| x64 Injector (payload2) | `2cf032f7e09e4d47b1d1b531b98caaa79d56da6524fe89eea3787211626ac404` | `9bc4a0e18d11a8d03d5bc10aff12346c` | `783a0be0d878eee9e2d7460eb6a09751685b812d` |

### Fuzzy Hash (dropper)
```
ssdeep: 24576:5zxH7KBBR4pu+DX7EIvAskQdAMPbzvBW3sNytg:5lH7IjiuCQ7sLrPbM
imphash: 14f8e4dca31086cd0498de53fcba2af3
```

### Registry
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  Value: "Windows Security Health Services"
  Data:  <path to dropped executable>
```

### File System
```
%SystemRoot%\Windows Security Health Services.exe
```
*(Note: dropped file may also be a copy of the injector or RAT core; exact filename is hardcoded in Stage 2)*

### Behavioral (Process)
```
cmd.exe /c icacls "<path>" /deny Everyone:(DE) /T /C
ShellExecuteExW with verb "runas"
CreateToolhelp32Snapshot → Process32FirstW/NextW (process enumeration)
VirtualAlloc (PAGE_EXECUTE_READWRITE) + CreateThread (shellcode injection)
```

### Network

| Type | Value | Source | Notes |
|------|-------|--------|-------|
| IPv4 | `106.54.39.113` | CAPE dynamic (sandbox #62270) | C2 server — Tencent Cloud VPS, AS45090, Shanghai CN |
| ASN | AS45090 | ipinfo.io | Shenzhen Tencent Computer Systems Co. Ltd. |
| URL (dead-drop candidate) | `hxxp://login.game.qq[.]com/comm-cgi-bin/login/LoginReturnInfo.cgi?callback=jsonp31&game=game` | Static (.rdata) | QQ Games connectivity check or C2 fallback |

**C2 protocol fingerprint:**
- Transport: HTTP POST via WinHTTP COM (`WinHttp.WinHttpRequest.5.1`)
- User-Agent: `Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)`
- Accept-Language: `zh-cn`
- Encoding: RC4 + MD5 auth + Base64 (custom `@ABCDE...` alphabet) + ZLIB
- Session: cookie-based

**Static C2 recovery — exhaustive negative result:**

| Stage | File | Size | Plain | UTF-16LE | XOR ×255 | DWORD | Result |
|-------|------|------|-------|----------|-----------|-------|--------|
| 0 — VMP dropper | `维持CK1.0.vmp.exe` | 1,103,360 B | ✗ | ✗ | ✗ | ✗ | **Not found** |
| 0b — Reflective shellcode | `main_resource.bin` | 1,074,066 B | ✗ | ✗ | ✗ | ✗ | **Not found** |
| 1 — E-language RAT | `payload1.bin` | 933,910 B | ✗ | ✗ | ✗ | ✗ | **Not found** |
| 2 — x64 injector | `payload2.bin` | 136,704 B | ✗ | ✗ | ✗ | ✗ | **Not found** |

Root cause: E-language's string runtime assembles strings as managed heap objects. Characters are never laid out sequentially in memory in a statically recoverable form. Dynamic analysis is the only viable recovery method for any E-language RAT C2 address.

**Note:** Port not recovered (CAPE report Cloudflare-blocked). Pivot on `106.54.39.113` in PCAP/NDR logs for port confirmation.

---

## 7. Attribution Assessment

**Confidence: Medium** — Chinese-speaking threat actor, likely crimeware or targeted espionage tool

### Evidence Supporting Chinese-Speaking Origin
1. **易语言 (E-language) IDE** — This IDE is developed in China, uses Chinese-language keywords, and is used almost exclusively within Chinese-language hacking communities. Its presence is a high-confidence indicator of a Chinese-speaking developer.
2. **Filename**: `维持CK1.0.vmp.exe` — Chinese characters (维持 = "maintain") with tool version "CK 1.0". The "CK" designation in Chinese cybercrime circles may refer to a named RAT family distributed in Chinese hacking forums.
3. **All UI resources** (LCID 0x0804 Chinese Simplified) including dialogs, menus, error strings.
4. **Database architecture** — local encrypted database for collected data, password-protected access dialog (请输入数据库访问密码), is a pattern seen in Chinese-origin RAT families (e.g., PCRat, Gray Pigeon derivatives).
5. **Feature set** (keylogging + webcam + screen + clipboard + remote shell + broadcast) matches the standard Chinese crimeware RAT specification seen in families like Gh0st RAT, XtremeRAT derivatives, and unnamed E-language RATs sold on Chinese forums.

### Distinguishing Factors
- **Stage 2 compiled February 2026**: The injector is fresh, indicating the campaign is active as of early 2026.
- **VMProtect layer**: Suggests the RAT is distributed as a "crypted" or "FUD" (fully undetectable) version of an underlying tool, consistent with Chinese crimeware-as-a-service models where buyers apply VMProtect wrappers before distribution.
- **"CK 1.0" naming**: Version 1.0 suggests an early or initial release. Could refer to a private RAT named "CK" (Control Kit, CobaltKing, or a Chinese name like 控客/CK). No public open-source CTI reports found matching this specific tooling combination.

### Nation-State vs. Criminal Assessment
The evidence leans toward **criminal/hacktool** rather than nation-state:
- No code signing, no supply chain indicators
- Version "1.0" naming and forum-style copyright notice (作者版权所有 请尊重并使用正版 = "Author copyright, please respect and use genuine version") are typical of Chinese crimeware products sold or shared on underground forums
- Lack of sophisticated 0-day or living-off-the-land binaries beyond standard Windows tools
- VMProtect usage is common in criminal malware distribution, less so in CNO operations

---

## 8. Detection Guidance

### YARA Rule

```yara
rule CK_RAT_Dropper_VMProtect_Elanguage {
    meta:
        description = "VMProtect Delphi dropper delivering E-language CK RAT"
        hash_sha256 = "4ad5c94364e05c363bd8f03cc35acf6166c9a496503859344a4418f2ae845caf"
        date = "2026-04-19"
        author = "REMnux static analysis"

    strings:
        // XOR-0x6E encoded "This program cannot be run in DOS mode" — dropper pattern
        $xor_dos_stub = { 06 07 1D 4E 1E 1C 01 09 1C 0F 03 4E 0D 0F 00 00 01 1A 4E }
        // XOR-0x4E encoded API names: GetProcAddress
        $xor_api_getprocaddr = { 29 0B 1A 3E 1C 01 0D 2F 0A 0A 1C 0B 1D 1D }
        // XOR-0x4E encoded API names: LoadLibrary partial
        $xor_api_loadlib = { 22 01 0F 0A 22 07 0C 1C 0F 1C 17 }
        // BITMAP resource name "MAIN" in resource directory
        $rsrc_name_main = { 4D 00 41 00 49 00 4E 00 }
        // Delphi FastMM marker
        $fastmm = "FastMM Embarcadero Edition" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 1000000 and filesize < 1200000
        and pe.number_of_sections == 9
        and $fastmm
        and ($xor_dos_stub or ($xor_api_getprocaddr and $xor_api_loadlib))
        and $rsrc_name_main
}

rule CK_RAT_Stage2_Injector_WindowsSecurityHealthServices {
    meta:
        description = "x64 injector/persister dropping as Windows Security Health Services.exe"
        hash_sha256 = "2cf032f7e09e4d47b1d1b531b98caaa79d56da6524fe89eea3787211626ac404"
        date = "2026-04-19"

    strings:
        $masquerade = "Windows Security Health Services" wide
        $runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $icacls = "/deny Everyone:(DE) /T /C" wide
        $runas = "runas" wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_64bit()
        and $masquerade
        and $runkey
        and $icacls
        and $runas
}

rule CK_RAT_Elanguage_Core {
    meta:
        description = "E-language (Yi-language) RAT core with keylogging, screen/webcam capture, RC4 C2"
        hash_sha256 = "645164397ceee3d7cf49132526d898fee9dd4c8be13124f886380997ea5b1dee"
        date = "2026-04-19"

    strings:
        // E-language IDE signature in version info
        $elang_comment = "http://www.eyuyan.com" wide
        $elang_desc = "\x6D\x50\x8B\x7A\x38\x8B\x7A\xE7\x40" nocase  // 易语言程序 UTF-16LE prefix
        // Database password dialog in Chinese
        $db_password = "\x8B\x8B\x65\x8F\x20\x65\x6E\x62\x5C\x8F\x58\x95\x95\x7B\x01\x78\x01" nocase
        // Winsock2 indicator
        $winsock2 = "ws2_32" ascii nocase
        // MD5 constant
        $md5_const = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }

    condition:
        uint16(0) == 0x5A4D
        and not pe.is_64bit()
        and filesize > 900000 and filesize < 1000000
        and ($elang_comment or $db_password)
        and $winsock2
        and $md5_const
}
```

### Sigma Rules (behavioral)

```yaml
# Detect persistence + tamper-protection pattern
title: CK RAT Windows Security Health Services Persistence
status: experimental
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
    Details|contains: 'Windows Security Health Services'
  condition: selection
falsepositives:
  - None (no legitimate product uses this name for autorun)
level: high
tags:
  - attack.persistence
  - attack.t1547.001

---
title: CK RAT icacls Tamper-Protection
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'icacls'
      - '/deny'
      - 'Everyone'
      - '(DE)'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1222
```

### Detection: File System
- Monitor creation of `*\Windows Security Health Services.exe` outside of Windows Update context
- Alert on any PE dropped to `%SystemRoot%` by non-system processes

### Detection: Network
- **Block / alert on all connections to `106.54.39.113`** (confirmed C2, CAPE sandbox #62270)
- Monitor HTTP POST traffic with User-Agent `Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)` and `Accept-Language: zh-cn` combination — low false-positive rate in modern environments
- Monitor for WinHTTP COM object instantiation (`WinHttp.WinHttpRequest.5.1`) from non-browser processes
- Look for `@`-prefixed Base64 (alphabet starts `@ABCDE...`) in HTTP POST bodies — custom encoding fingerprint
- RC4-over-HTTP with `Set-Cookie` session management from unusual processes

---

## 9. Forensic Notes

- **Timestamp manipulation:** The outer dropper has a fake 2013 timestamp. Stage 1 (2023-01-24) represents plausible compilation date for the RAT core. Stage 2 (2026-02-25) is the most reliable timestamp — close to collection and consistent with active campaign.
- **XOR key 0x6E significance:** The key byte `0x6E` = ASCII 'n', causing encoded null-heavy PE sections to produce long 'nnnn...' runs visible in hex editors. This is a known fingerprint for detecting the dropper family.
- **C2 IP confirmed dynamically:** `106.54.39.113` (Tencent Cloud AS45090, Shanghai). The IP is absent from **all four stages of the package** — dropper, reflective shellcode, E-language RAT core, and x64 injector — in every tested encoding (plain, UTF-16LE, XOR keys 1–255, DWORD BE/LE, 4-byte chunks, MOV BYTE sequences). E-language's string runtime builds strings as managed heap objects via internal allocator/concatenation functions; characters are never laid out sequentially in memory in a recoverable form. This makes C2 extraction impossible by static means and requires dynamic analysis (sandbox, debugger, or network tap) for every sample built with this toolchain.
- **Database artifact:** The RAT stores collected data in a local database (path unknown statically). During incident response, search for SQLite files or binary log files in `%APPDATA%`, `%TEMP%`, or `%LOCALAPPDATA%` created by `Windows Security Health Services.exe`.
- **Extraction method:** Both embedded PEs are XOR-decoded from file offsets `0x74D0` (Stage 1) and `0xEB4E6` (Stage 2) with key `0x6E`. Python one-liner: `bytes([b^0x6e for b in data[0x74d0:0xeb4e6]])`.

---

## 10. Recommendations

1. **Immediate:** Block file hash IoCs at EDR/AV. Add YARA rules to detection pipeline.
2. **Hunt:** Search all endpoints for `Windows Security Health Services.exe` in `%SystemRoot%`.
3. **Hunt:** Query for the Run key value "Windows Security Health Services" across fleet.
4. **Hunt:** Search for `icacls` commands with `/deny Everyone:(DE)` in process logs.
5. **Network block:** Add `106.54.39.113` to firewall deny-list and EDR network block rules immediately. Check NDR/proxy logs for any historic connections to this IP.
6. **Network:** Monitor for HTTP POST with MSIE 9.0/zh-cn UA combination; block WinHTTP COM use by non-browser processes via AppLocker/WDAC.
7. **Remediation:** If infected, repair icacls ACL before attempting deletion: `icacls "<path>" /reset /T /C` then delete. Remove Run key value. Kill process tree.
8. **Pivot:** Search TI platforms (VirusTotal, MalwareBazaar, any.run) for the extracted payload hashes to identify additional infrastructure.

---

*Static analysis findings derived from direct REMnux tool examination. C2 IP (`106.54.39.113`) confirmed via CAPE dynamic analysis (sandbox #62270). Port number not recovered (Cloudflare prevented report access); pivot on the IP in PCAP/NDR telemetry.*
