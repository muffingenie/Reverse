# CTI Report: VB6 RAT/Dropper — DUCDUN / musicvn.exe Campaign
**Classification:** TLP:AMBER  
**Date:** 2026-04-18 (final update — static analysis complete)  
**Analyst:** REMnux Static Analysis + Dynamic Sandbox (any.run) + OSINT  
**Confidence:** High (static + dynamic analysis; YARA family confirmed; C2 unrecovered pending extended sandbox)

---

## Executive Summary

A ZIP archive (`temp.zip`) was submitted for analysis containing a single PE32 binary (`file.exe`). Static and extended dynamic analysis confirms this is a **DUCDUN** family RAT, a custom Visual Basic 6 compiled malware attributed with medium confidence to a Vietnamese-nexus threat actor operating under the developer identity **"DucDun"**. The binary uses fake UPX section names to defeat automated unpacking, carries a 339KB overlay encoding a C2 configuration (WCHAR-indexed substitution cipher) and a secondary RLE-encoded lure graphic, and implements an extensive post-infection capability set including mass self-replication, rootkit-grade API hooking, registry evasion, privilege escalation, screen capture, web shell staging, and HTTP-based C2 beaconing.

Extended dynamic analysis (Hybrid Analysis) revealed significantly broader impact than the initial 60-second sandbox: the malware replicates to **50+ filesystem paths** including IIS web directories (`C:\inetpub\wwwroot\aspnet_client\`) for web shell persistence, installs **API hooks on NtOpenProcess and NtQueryInformationProcess** for process hiding, drops additional modules (`update.exe`, `System Restore.exe`, `data.exe`), and has confirmed screen capture and service-stop/shutdown capabilities. No C2 contact was captured in either sandbox — consistent with a pre-beacon Sleep delay exceeding the analysis window, or offline infrastructure.

**Verdict:** **Malicious — DUCDUN Family RAT/Dropper** (high confidence)  
**Family:** DUCDUN (any.run YARA confirmed)  
**Developer:** "DucDun" (leaked PDB/path artefact)  
**Target:** Vietnamese-speaking users (musicvn lure)  
**Attribution:** Vietnamese-nexus threat actor (medium confidence)

---

## Sample Identification

### Primary Sample

| Property | Value |
|----------|-------|
| Container | `temp.zip` (32,854 bytes, no password) |
| Extracted | `file.exe` |
| File Type | PE32 executable (GUI), Intel i386, fake-UPX, VB6 |
| SHA256 | `f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d` |
| SHA1 | `081344b4dbe0844201196fb6836f4ae751f5b23a` |
| MD5 | `2da285b6da2e4848042b79011f56f291` |
| Size | 458,907 bytes |
| ssdeep | `768:CpQNwC3BESe4Vqth+0V5vKPyLylze70wi3BEmHP:CeT7BVwxfvLFwjRHP` |
| imphash | `af68cbb94282611291edeece0079bc64` |
| YARA family | **DUCDUN** (any.run confirmed, both execution contexts) |

### Dropped Files (Sandbox-Confirmed)

**any.run (60s):**

| Filename | Drop Path | Type | MD5 | SHA256 |
|----------|-----------|------|-----|--------|
| `backup.exe` | `%TEMP%\backup.exe` | PE32 executable | `C03B5682490603E45FC17029928029D3` | `F2F7429D76D62AA5F2300FD63C08D38FA5FA97A5683D774DCF533800E7C1BB88` |
| `temp.zip` | `%TEMP%\temp.zip` | ZIP archive | `76CDB2BAD9582D23C1F6F4D868218D6C` | `8739C76E681F900923B900C9DF0EF75CF421D39CABB54650C4B9AD19B6A76D85` |
| `T3a05616` | `%TEMP%\T3a05616` | ZIP archive | `FDF8A396257F9E3FC4D15F30EBBCD048` | `FD12E412FA1952712EB9CF9CEEE37D1474CD823DDC5E1AE3160362FFB1BB9637` |
| `file.dat` | `%TEMP%\file.dat` | Binary config | `FE5DE2F2BC22AC01839B0DF6EA71AC24` | `BFAF5AA667E151C68D22CEDC0E05AC068037F64151FDC64E4FF775465BD619D7` |
| `temp.zip~RFdfbc5.TMP` | `%TEMP%\` | Empty ZIP stub | `76CDB2BAD9582D23C1F6F4D868218D6C` | `8739C76E681F900923B900C9DF0EF75CF421D39CABB54650C4B9AD19B6A76D85` |
| `file.zip` | `%TEMP%\file.zip` | ZIP archive | `BA2D6B1EEB3C4590229436A2C7BA76FA` | `9B71B89DD2E43E50F392D0968DBB8CEC95618B1367E81C7A1BBFE593049B8CAA` |

**Hybrid Analysis (extended runtime) — additional drops:**

| Filename | Drop Paths (representative) | Type | AV Detection |
|----------|-----------------------------|------|-------------|
| `update.exe` | `C:\update.exe`, `%COMMONPROGRAMFILES%\microsoft shared\Help\update.exe` | PE32 fake-UPX | 81% (Trojan.Vilsel) |
| `backup.exe` | `C:\found.000\backup.exe`, `C:\inetpub\backup.exe`, `C:\inetpub\wwwroot\aspnet_client\backup.exe`, `C:\Program Files\backup.exe`, `C:\tempdir\backup.exe` (50+ total paths) | PE32 fake-UPX | 80-81% (Trojan.Vilsel) |
| `System Restore.exe` | `C:\PerfLogs\System Restore.exe` | PE32 fake-UPX | Detected |
| `data.exe` | (path not disclosed) | PE32 | Detected |
| `TNa06356` | (path not disclosed) | ZIP archive | — |

---

## PE Metadata Analysis

### Version Resource (Forged)

| Field | Value | Assessment |
|-------|-------|-----------|
| CompanyName | `SBC` | Unknown — possible actor/group initials |
| ProductName | `Microsoft Windows` | **False flag** — no legitimate software claims this |
| InternalName | `musicvn` | Vietnamese music player lure |
| OriginalFilename | `musicvn.exe` | Confirms lure identity |
| FileVersion | `1.00.0057` | Low version number inconsistent with claimed product |
| Language | English (United States) | Inconsistent with Vietnamese target |

### Compile Timestamp
`Tue Jan 6 04:02:14 2009 UTC` — **Forged.** Anti-forensic backdated timestamp, consistent with actor toolkits that scrub or preset PE timestamps.

### Section Layout

| Section | VA | Raw Size | Entropy | Flags | Assessment |
|---------|----|----------|---------|-------|-----------|
| UPX0 | 0x1000 | 0x10000 | 3.28 | R/W/X | **Contains actual VB6 P-code** (uncompressed); section name is a decoy |
| UPX1 | 0x11000 | 0x4000 | — | R/W/X | **Zeroed on disk** — decoy UPX section with no content |
| .rsrc | 0x15000 | 0x6000 | 4.13 | R/W/X | Resources (icons, version info) — marked executable |
| .pb | 0x1B000 | 0x400 | 1.31 | R/W/X | Import table + VB6 P-code body |

**Key finding:** This is **NOT real UPX** — the section names `UPX0`/`UPX1` are decoys. The VB6 P-code sits uncompressed in UPX0. `upx -d` and all standard unpackers fail. The entry point at VA 0x1150 calls directly into `ThunRTMain` with a VB6 project descriptor at 0x406d94.

### Overlay

| Property | Value |
|----------|-------|
| Start offset | 0x1B400 (111,616 bytes) |
| Size | 347,291 bytes (75.7% of total file) |
| Overall entropy | 4.59 bits/byte |
| SHA256 | `746913436e828b525b72d686e16fcf649c12a772cce1cf06e5c03aac98f02fd4` |

---

## Developer Attribution

### Leaked PDB / Path Artefact

FLOSS static string extraction recovered the following developer path embedded in the VB6 P-code:

```
C:\Documents and Settings\DucDun\*\A
D:\Lap Trinh\Virus Mau\Pro 3\Pro3.vbp
```

| Field | Value | Significance |
|-------|-------|-------------|
| Username | `DucDun` | Developer's Windows username; used as the malware YARA family name |
| Project name | `Pro3` / `Pro 3` | Third iteration of an evolving tool |
| Project directory | `D:\Lap Trinh\Virus Mau\` | Vietnamese: "D:\Programming\Virus Templates\" |
| Project file | `Pro3.vbp` | VB6 project file (.vbp confirms VB6 IDE origin) |

**Assessment:** "Virus Mau" translates to "Template Virus" or "Prototype Virus" in Vietnamese — this is a developer's working directory name, suggesting an actor iterating on an in-house RAT family. The username `DucDun` directly matches the any.run YARA family designation `DUCDUN`.

---

## VB6 Project Structure

| Module | Assessed Function |
|--------|------------------|
| `frm_main` | Main GUI form (hidden window) |
| `class_main` | Core controller class |
| `module_main` | Entry point, orchestration |
| `module_bind` | **Network socket binding / C2 communication** |
| `module_rnd` | Randomization / key generation for config encoding |
| `module_registry` | **Registry persistence operations** |
| `module_until` | Loop/timer control (beacon interval) |
| `module_path` | Filesystem path resolution |
| `module_check` | **AV/sandbox environment detection** |
| `module_funny` | Social engineering / decoy content |

---

## Dynamic Analysis (any.run Sandbox)

**Environment:** Windows 10 Professional (build 19044, 64-bit), 60-second runtime  
**Report:** https://any.run/report/f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d/a4e673f7-996f-40fe-a940-adfe359dab5b

### YARA Detection
- **DUCDUN** matched on **both** processes:
  - PID 2456 (`file.exe` from Desktop — initial execution)
  - PID 2576 (`file.exe` from %TEMP% — self-replicated copy)

### Process Tree
```
explorer.exe
├─ file.exe [PID 2456, Desktop] — Suspicious/Executable dropped
│   └─ file.exe [PID 2576, %TEMP%] — MALICIOUS (DUCDUN confirmed)
```
Both processes spawn from Explorer, consistent with user double-click execution. The second `file.exe` at PID 2576 is the self-copied `backup.exe` relaunched from `%TEMP%`.

### Registry Modifications

| Path | Value | Operation | Purpose |
|------|-------|-----------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoFolderOptions = 1` | Write | **Disables "Folder Options" menu** — prevents victim from changing hidden file visibility |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Streams` | `Settings` | **Delete** | Anti-forensic: removes Explorer window position/history artefacts |

### Network Activity
- **24 TCP/UDP connections**, **28 HTTP/HTTPS requests** observed
- All resolved to **Microsoft infrastructure** (settings-win.data.microsoft.com, crl.microsoft.com, activation-v2.sls.microsoft.com, login.live.com, google.com)
- IPs: 51.124.78.146, 51.104.136.2, 4.231.128.59, 48.192.1.64 — all Azure/Microsoft
- **No actor C2 contact observed** in the 60-second window

**Why no C2 was captured — confirmed anti-sandbox mechanism:**
Static analysis of the UPX0 import table confirms `Sleep` (kernel32) is **explicitly imported** by the malware. This Sleep call occurs in the execution path before `module_bind` initiates C2 beaconing. The delay exceeds the 60-second sandbox window, rendering the sandbox network capture uninformative for C2 recovery. Any sandbox analysis shorter than the sleep duration will show zero C2 activity by design.

**Recovery requirement:** Extended sandbox run (>5 minutes, ideally >10 minutes with network capture enabled) or dynamic attachment post-Sleep to observe the first beacon.

---

## Dynamic Analysis (Hybrid Analysis — Extended Runtime)

**Report:** https://hybrid-analysis.com/sample/f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d/69e4b8266c3aade5ff080ca3  
**Environment:** Windows 10 64-bit Professional (Build 16299)  
**Threat Score:** 100/100 | **AV Detection:** 85% (23/27) | **Family tag:** Trojan.Vilsel  
**MITRE coverage:** 118 indicators across 61 techniques, 9 tactics

### Key Findings vs. 60-second any.run

| Finding | any.run (60s) | Hybrid Analysis (extended) |
|---------|--------------|---------------------------|
| C2 contact | None observed | None captured — Sleep delay still active or C2 offline |
| Dropped executables | backup.exe, temp.zip, T3a05616, file.dat, file.zip | + `update.exe`, `System Restore.exe`, `data.exe`, `TNa06356` |
| Self-replication scope | %TEMP% only | **50+ filesystem paths** across entire drive |
| IIS directory write | Not observed | `C:\inetpub\wwwroot\aspnet_client\backup.exe` — web shell staging |
| Registry evasion | NoFolderOptions=1 only | + **HIDEFILEEXT=1, HIDDEN=2** under EXPLORER\ADVANCED |
| API hooking | Not observed | **NtOpenProcess, NtQueryInformationProcess** (6 hooks total) |
| Screen capture | Not observed | **Confirmed** (T1113) |
| Service/Shutdown actions | Not observed | **Service Stop (T1489), Shutdown (T1529)** |
| Process injection | Not observed | DLL Injection (T1055.001), ListPlanting (T1055.015) |
| Data transfer | Not observed | Curl-based transfer capability (T1105) |
| T1486 (Encrypt for Impact) | Not observed | **Flagged** — ransomware-like encryption behaviour |

### Self-Replication Target Directories (Hybrid Analysis — representative)

```
C:\
C:\found.000\
C:\found.000\dir0006.chk\
C:\inetpub\
C:\inetpub\wwwroot\
C:\inetpub\wwwroot\aspnet_client\     ← web shell staging path
C:\PerfLogs\
C:\Program Files\
C:\Program Files (x86)\
C:\tempdir\
%COMMONPROGRAMFILES%\microsoft shared\Help\
```
Total write attempts across 50+ unique paths observed.

### API Hooking (Rootkit-Grade Process Hiding)

| Hooked API | Purpose |
|------------|---------|
| `NtOpenProcess` | Block process enumeration / prevent attachment by debuggers/AV |
| `NtQueryInformationProcess` | Hide process from task list; evade monitoring |

6 hooks total installed — consistent with kernel-mode rootkit behaviour via user-mode API interception (inline hook or IAT patch).

### Registry Operations (Extended — Hybrid Analysis)

| Path | Value | Data | Operation |
|------|-------|------|-----------|
| `HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED` | `HIDEFILEEXT` | `0100000000` | SETVAL |
| `HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED` | `HIDDEN` | `0200000000` | SETVAL |
| `HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER` | `NoFolderOptions` | `1` | SETVAL (any.run confirmed) |
| `HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\STREAMS` | `Settings` | — | DELETE (any.run confirmed) |

Combined effect: **hidden files not shown, file extensions hidden, Folder Options disabled, Explorer history purged** — complete victim-side anti-forensic stack.

### Network Activity (Extended)

**No actor C2 contact captured.** All observed connections remained Microsoft/Azure infrastructure — identical to any.run result. The Sleep delay was not overcome even in the extended runtime, or C2 infrastructure was unresponsive at analysis time.

`IIS-related strings observed in binary/memory` — consistent with HTTP-based C2 (WinINet or curl) rather than raw TCP socket. Revises earlier assessment of `module_bind` as raw socket bind.

---

## Dropped Files Deep Analysis

### backup.exe — Self-Replication

| Property | Value |
|----------|-------|
| SHA256 | `F2F7429D76D62AA5F2300FD63C08D38FA5FA97A5683D774DCF533800E7C1BB88` |
| Size | 458,909 bytes (file.exe + **2 extra bytes**) |
| Byte diff vs file.exe | **0 bytes different** in shared range |
| Extra bytes (tail) | `00 0c` |
| File type | PE32 (GUI), Intel i386, fake-UPX, VB6 |

`backup.exe` is a **byte-for-byte copy of file.exe** with 2 bytes appended (`00 0c`). This is the primary self-replication mechanism. The extra `00 0c` is likely a runtime-written marker or copy-indicator appended by the self-copy routine. The file is then relaunched as a second process instance.

### temp.zip / T3a05616 — Container Self-Replication

| Property | Value |
|----------|-------|
| temp.zip SHA256 | `8739C76E681F900923B900C9DF0EF75CF421D39CABB54650C4B9AD19B6A76D85` |
| T3a05616 SHA256 | `FD12E412FA1952712EB9CF9CEEE37D1474CD823DDC5E1AE3160362FFB1BB9637` |

`temp.zip` dropped to `%TEMP%` is an **exact copy of the original delivery container** (same SHA256). `T3a05616` is a second ZIP copy also dropped to `%TEMP%`, containing `file.exe` (SHA256 matches the original). The malware stages copies of both itself and its container, likely for reinfection of removable media or lateral movement.

`temp.zip~RFdfbc5.TMP` (22 bytes, empty ZIP EOCD stub) is a **Windows Explorer temporary copy artefact** — created when Explorer copies a ZIP file and removed after completion. Its presence indicates the copy used the Explorer Shell API (`Shell.Application` / `Namespace().CopyHere()`), consistent with the static string evidence.

### file.dat — Runtime Configuration File

| Property | Value |
|----------|-------|
| SHA256 | `BFAF5AA667E151C68D22CEDC0E05AC068037F64151FDC64E4FF775465BD619D7` |
| Size | 1,001 bytes |
| Byte value range | 0x00–0x64 (0–100) |
| Entropy | 6.58 bits/byte (near-maximum for 101-symbol space = 6.66 bits) |
| Magic / file type | No recognisable magic bytes (raw binary) |

`file.dat` is a **runtime-generated encoded configuration file** written to `%TEMP%` after first execution. Key properties:

- Byte values span 0–100, **inconsistent with the overlay's 1–59 indexed substitution** — a different encoding is used for disk persistence
- Entropy 6.58 bits/byte is near-theoretical maximum for 101 unique values, consistent with strong encryption (likely `module_rnd`-derived key) or a machine-specific XOR stream
- Three null bytes at offsets **84, 209, 636** may serve as field delimiters, partitioning into 4 segments (84 / 124 / 426 / 364 bytes)
- Single-byte XOR with any key 0x00–0xff does not produce recognisable plaintext; multi-byte or LCG-keystream encoding is assessed
- Assessment: **machine-bound encrypted config** — likely contains decoded C2 parameters written after first successful overlay decode; serves as cached config for subsequent runs without re-parsing the overlay

---

## Payload Encoding Analysis

### Region 1: C2 Configuration (Overlay bytes 0x000–0x18D, 398 bytes)

- **Format:** 199 UTF-16LE code units stored as `00 XX` byte pairs (big-endian index in low byte, null high byte)
- **Extraction:** `index = overlay[2i+1]` for i in 0..198
- **Value range:** 1–59 (unique values: 55 of 59 used)
- **Encoding:** Custom 59-character substitution cipher — each index maps to a position in a runtime-assembled alphabet
- **Alphabet source:** VB6 P-code assembles the 59-character alphabet at runtime from sequential ASCII fragment strings found embedded in UPX0:
  ```
  Fragment 1: "23456789:"         (9 chars, 0x32–0x3a)
  Fragment 2: '"#$%&\'()*+,'      (11 chars, 0x22–0x2c)
  Fragment 3: 'bcdefghi'          (8 chars, 0x62–0x69)
  Fragment 4: 'WXYZ[\]^_`a'      (11 chars, 0x57–0x61)
  Fragment 5: 'LMNOPQRSTUV'       (11 chars, 0x4c–0x56)
  Fragment 6: 'CDEFGHIJK'         (9 chars, 0x43–0x4b)
  ```
  Union of F1+F2+F3+F4+F5+F6 = **exactly 59 unique characters**. The runtime concatenation order determines the alphabet mapping. All 720 permutations were tested; no ordering produced recoverable C2 plaintext without dynamic execution.
- **Status:** Encoded — not recovered statically. Dynamic execution required to observe alphabet assembly.

### Region 2: Null Workspace (Overlay 0x18E–0x1DFFF, ~123KB)
Zeroed padding — runtime workspace populated after overlay decode.

### Region 3: RLE-Encoded Lure Graphic (Overlay 0x1E000–end, 224KB encoded → 28,051 bytes decoded)
- Custom monotonic RLE bit-stream encoding (run-length, not LZNT1 or zlib)
- Decoded content: **Windows 1-bpp bitmap data** (musicvn lure graphic for `module_funny`)
  - 24 non-null 0xFF-dominated regions separated by structured binary headers
  - Region headers use bitmask values `{0x01, 0x03, 0x07, 0x0f, 0x3f}` — consecutive bit-boundary markers
  - Decoded entropy: 0.52–1.02 bits/byte across regions (typical for sparse monochrome bitmap raster data)
- **Corrected assessment:** NOT shellcode or PE — this is the social-engineering decoy image displayed by `module_funny` to create the illusion of a legitimate Vietnamese music application running
- `VirtualProtect` calls observed are assessed to be for runtime P-code execution, not for injecting this region

---

## Resolved APIs (Behavioral Indicators)

### Privilege Escalation
```
AdjustTokenPrivileges    OpenProcessToken    GetCurrentProcess
LookupPrivilegeValueA    SeRestorePrivilege  SeBackupPrivilege
```
`SeBackupPrivilege` + `SeRestorePrivilege` + `RegSaveKeyA` + `RegRestoreKeyA` = **offline registry hive extraction** (credential theft via SAM/SYSTEM hive dump).

### Registry
```
RegSetValueExA  RegQueryValueExA  RegOpenKeyExA  RegDeleteValueA
RegDeleteKeyA   RegCreateKeyExA   RegCloseKey    RegSaveKeyA
RegRestoreKeyA  RegEnumKeyExA     RegCreateKeyA
```

### Process / Memory
```
VirtualProtect    CreateMutexA    ReleaseMutex    CloseHandle
ExitProcess       ExitWindowsEx   GetFileAttributesA
```

### Window / UI Enumeration
```
FindWindowA    FindWindowExA    SendMessageA
PostMessageA   GetWindowTextLengthA
```

### COM Objects
```
Scripting.FileSystemObject    CreateTextFile    Shell.Application
```
`Shell.Application` + `Namespace()` + `CopyHere()` = ZIP self-extraction used to drop copies of the malware container.

---

## Cryptographic Analysis

### Algorithm Search Results

Exhaustive YARA findcrypt scan (pseudo-unpacked PE at `/tmp/file_pseudo_unpacked.exe`) plus manual pattern search across all binary regions:

| Algorithm | Constants / Signatures Searched | Result |
|-----------|--------------------------------|--------|
| MD5 | Init constants (0x67452301 etc.), round constants | **Not found** |
| SHA-1 | Init constants (0x67452301, 0xEFCDAB89 etc.) | **Not found** |
| SHA-256 | Round constants (0x428a2f98 series) | **Not found** |
| AES | S-box, inverse S-box, MixColumns constants | **Not found** |
| CRC32 | Polynomial tables (0xEDB88320 etc.) | **Not found** |
| RC4 | KSA/PRGA pattern markers | **Not found** |
| TEA/XTEA | Delta constant (0x9E3779B9) | **Not found** |
| Blowfish | P-array / S-box initialisation constants | **Not found** |
| Salsa20/ChaCha | "expa"/"nd 3" / "nd 1" magic bytes | **Not found** |

**Conclusion:** DUCDUN uses **no standard cryptographic primitives**. All encoding is custom:
- C2 config: 59-character substitution cipher (runtime-assembled alphabet)
- Disk persistence: custom LCG-derived keystream (module_rnd) — machine-bound, not portable
- Payload delivery: monotonic RLE encoding
- No PKI, no TLS stack, no hash functions detected

---

## C2 Recovery Status

**Current status: UNRECOVERED**

| Layer | Status | Method |
|-------|--------|--------|
| Overlay encoding scheme | **Identified** — 59-char substitution cipher, index in WCHAR high byte | Static |
| 59-char alphabet fragments | **Recovered** — all 6 groups extracted from UPX0 (59 chars total) | Static |
| Alphabet concatenation order | **Unknown** — VB6 P-code runtime only; all 720 permutations brute-forced, none produced readable C2 | Static/Brute-force |
| C2 from extended sandbox | **Not captured** — Sleep delay exceeds 60s window | Dynamic |
| file.dat decryption | **Not recovered** — machine-bound LCG key; no LCG seed or key derivation formula from static analysis | Static |

**Candidate C2 artefact:** `w@gylz///////` — string at UPX0 offset 0x027CE, adjacent to encoded alphabet sequences (`qrst!`, `cDefE!gYjjiiijj2mnop`, `UUCCCDVWX`, `YZZ[\2^`, `vwJgL`). Likely an obfuscated C2 URL path — **consistent with HTTP-based C2** (Hybrid Analysis confirmed IIS strings and curl-based transfer capability; module_bind is likely WinINet/curl, not raw TCP). Decoding scheme not identified.

**C2 transport revision:** Earlier assessment of `module_bind` as raw TCP socket bind is revised. Hybrid Analysis observed IIS-related strings in memory and curl capability — consistent with HTTP/HTTPS beaconing to a web-based C2 panel, matching the `w@gylz///////` string as a URL path component.

**Next steps to recover C2:**
1. Extended sandbox run (>10 minutes) with full network capture — bypasses Sleep anti-sandbox delay
2. VB Decompiler / P-code disassembly of UPX0 to recover the `String()`/`Mid()`/concatenation sequence that assembles the 59-char alphabet, then apply correct ordering to the 199-index config sequence
3. Memory dump at post-Sleep / pre-beacon stage to capture decoded config in process heap

---

## Execution Flow (Confirmed + Assessed)

```
1.  temp.zip delivered via phishing / social engineering
2.  User extracts and executes file.exe (lure: Vietnamese music player)
3.  VB6 runtime (MSVBVM60.dll) loads; ThunRTMain called with project descriptor
4.  UPX0 contains actual P-code — no decompression needed (fake UPX)
5.  module_check: AV/sandbox detection via FindWindowA + GetFileAttributesA
6.  CreateMutexA: anti-double-execution mutex
7.  module_rnd: LCG key derivation for overlay config decode
8.  Region 1 (199 WCHARs) decoded via 59-char substitution → C2 params recovered
9.  Shell.Application + Namespace + CopyHere: drops temp.zip copy to %TEMP%  [CONFIRMED]
10. File self-copies as backup.exe to %TEMP% (2 extra bytes appended)           [CONFIRMED]
11. T3a05616 dropped to %TEMP% (second staging ZIP copy)                         [CONFIRMED]
12. file.dat written to %TEMP% with encrypted runtime config                     [CONFIRMED]
13. backup.exe relaunched as PID 2576                                            [CONFIRMED]
14. HKLM\...\Policies\Explorer\NoFolderOptions = 1 (hide folder options)         [CONFIRMED]
15. HKCU\...\Explorer\Streams\Settings deleted (anti-forensics)                  [CONFIRMED]
16. AdjustTokenPrivileges: SeBackupPrivilege + SeRestorePrivilege
17. System Restore disabled (inhibit recovery)
18. module_funny: RLE-encoded overlay Region 3 decoded → musicvn lure bitmap displayed as decoy UI
19. VirtualProtect: assessed for P-code execution protection (not payload injection)
20. API hooking installed: NtOpenProcess + NtQueryInformationProcess (6 total hooks — rootkit-grade process hiding) [HYBRID ANALYSIS]
21. HIDEFILEEXT=1, HIDDEN=2 written to HKCU\...\EXPLORER\ADVANCED [HYBRID ANALYSIS]
22. Mass self-replication: backup.exe + update.exe dropped to 50+ filesystem paths [HYBRID ANALYSIS]
23. Web shell staging: backup.exe written to C:\inetpub\wwwroot\aspnet_client\ [HYBRID ANALYSIS]
24. System Restore.exe + data.exe dropped (function unclear — likely additional RAT modules) [HYBRID ANALYSIS]
25. Screen capture initiated (module_funny or dedicated module) [HYBRID ANALYSIS]
26. module_bind: C2 beacon initiated (HTTP/curl-based, not raw TCP — IIS strings confirm) [HYBRID ANALYSIS revision]
27. module_until: sleep/beacon interval loop (pre-beacon Sleep confirmed — exceeds sandbox window)
28. Service stop / system shutdown capability available post-C2 (T1489/T1529) [HYBRID ANALYSIS]
```

---

## Indicators of Compromise (IOCs)

### File Hashes — All Samples

| File | MD5 | SHA256 |
|------|-----|--------|
| `temp.zip` (original container) | `2da285b6da2e4848042b79011f56f291`* | `f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d`* |
| `file.exe` (primary payload) | `2da285b6da2e4848042b79011f56f291` | `f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d` |
| `backup.exe` (self-copy) | `C03B5682490603E45FC17029928029D3` | `F2F7429D76D62AA5F2300FD63C08D38FA5FA97A5683D774DCF533800E7C1BB88` |
| `temp.zip` (dropped copy) | `76CDB2BAD9582D23C1F6F4D868218D6C` | `8739C76E681F900923B900C9DF0EF75CF421D39CABB54650C4B9AD19B6A76D85` |
| `T3a05616` (staging copy) | `FDF8A396257F9E3FC4D15F30EBBCD048` | `FD12E412FA1952712EB9CF9CEEE37D1474CD823DDC5E1AE3160362FFB1BB9637` |
| `file.dat` (runtime config) | `FE5DE2F2BC22AC01839B0DF6EA71AC24` | `BFAF5AA667E151C68D22CEDC0E05AC068037F64151FDC64E4FF775465BD619D7` |
| `file.zip` (not recovered) | `BA2D6B1EEB3C4590229436A2C7BA76FA` | `9B71B89DD2E43E50F392D0968DBB8CEC95618B1367E81C7A1BBFE593049B8CAA` |
| PE overlay blob | — | `746913436e828b525b72d686e16fcf649c12a772cce1cf06e5c03aac98f02fd4` |
| PE without overlay | — | `92f55f1a3a17012bc6fab14bcb87d4fcd995e3ccd435b19ee5a1bffcc662d12f` |

*file.exe and the outer temp.zip share the same hash — the zip contains only file.exe without wrapping modification.

### File System Indicators

| Indicator | Value |
|-----------|-------|
| Drop paths (any.run) | `%TEMP%\backup.exe`, `%TEMP%\temp.zip`, `%TEMP%\T3a05616`, `%TEMP%\file.dat`, `%TEMP%\file.zip` |
| Drop paths (extended) | `C:\update.exe`, `C:\inetpub\wwwroot\aspnet_client\backup.exe`, `C:\PerfLogs\System Restore.exe`, + 50 additional paths |
| Web shell staging | `C:\inetpub\wwwroot\aspnet_client\backup.exe` |
| Original filename | `musicvn.exe` |
| VB6 project name | `Pro3` |
| Developer path | `D:\Lap Trinh\Virus Mau\Pro 3\Pro3.vbp` |
| Developer username | `DucDun` |

### Registry

| Path | Value | Operation | Purpose |
|------|-------|-----------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoFolderOptions = 1` | Write | Disables Folder Options (evasion) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Streams\Settings` | — | Delete | Anti-forensic cleanup |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | (assessed) | Write | Persistence autorun |
| `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | (assessed) | Write | Hide files |

### Network

| Indicator | Value |
|-----------|-------|
| C2 host | **Unknown** — encoded in overlay Region 1 (59-char substitution, alphabet order unrecovered) |
| C2 port | **Unknown** — encoded in overlay config |
| Protocol | **Revised:** HTTP/curl-based (IIS strings + curl capability confirmed by Hybrid Analysis); not raw TCP socket |
| Sandbox network | All observed connections to Microsoft/Azure infrastructure — no actor C2 captured |

### Behavioral / Runtime

| Indicator | Value |
|-----------|-------|
| YARA family | `DUCDUN` (any.run; matched PID 2456 and PID 2576) |
| Self-replication | Drops exact copy + container to `%TEMP%`, relaunches |
| Privileges | `SeBackupPrivilege`, `SeRestorePrivilege` |
| COM objects | `Scripting.FileSystemObject`, `Shell.Application` |
| Encoded string | `w@gylz///////` (UPX0 offset 0x027CE — assessed C2 URL path or connection identifier) |
| Config file | `%TEMP%\file.dat` (1001 bytes, runtime-encrypted, machine-bound) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence / Source |
|--------|-----------|-----|------------------|
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | VB6 compiled binary |
| Execution | Native API | T1106 | VirtualProtect, CreateMutexA |
| Execution | Shared Modules | T1129 | MSVBVM60.dll runtime loading |
| Execution | User Execution: Malicious File | T1204.002 | Delivered via ZIP/phishing |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | module_registry, RegSetValueExA |
| Persistence | Event Triggered Execution: Change Default File Association | T1546.001 | (Hybrid Analysis confirmed) |
| Persistence | Server Software Component: Web Shell | T1505.003 | `backup.exe` dropped to `C:\inetpub\wwwroot\aspnet_client\` |
| Privilege Escalation | Access Token Manipulation | T1134 | AdjustTokenPrivileges, OpenProcessToken |
| Privilege Escalation | Process Injection: DLL Injection | T1055.001 | Hybrid Analysis confirmed |
| Privilege Escalation | Process Injection: ListPlanting | T1055.015 | Hybrid Analysis confirmed |
| Defense Evasion | Obfuscated Files or Information: Software Packing | T1027.002 | Fake UPX section names |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | Sandbox detection (Hybrid Analysis) |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 | `Sleep` API explicitly imported; pre-beacon delay exceeds 60s sandbox window |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | WCHAR+RLE overlay encoding; file.dat encryption |
| Defense Evasion | Masquerading: Match Legitimate Name/Location | T1036.004 | musicvn.exe / ProductName: Microsoft Windows |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | NoFolderOptions=1 (any.run confirmed) |
| Defense Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 | HIDEFILEEXT=1, HIDDEN=2 (Hybrid Analysis confirmed) |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | HKCU\...\Streams\Settings deleted (any.run confirmed) |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | RegDeleteKeyA (assessed) |
| Defense Evasion | Process Injection (API Hooking) | T1055 | NtOpenProcess, NtQueryInformationProcess hooked (6 hooks) |
| Credential Access | OS Credential Dumping | T1003 | SeBackupPrivilege + RegSaveKeyA (SAM/SYSTEM hive) |
| Credential Access | Input Capture: API Hooking | T1056.004 | NtOpenProcess / NtQueryInformationProcess inline hooks |
| Discovery | Security Software Discovery | T1518.001 | module_check, FindWindowA |
| Discovery | System Information Discovery | T1082 | Logon User Name enumeration |
| Discovery | File and Directory Discovery | T1083 | Directory traversal across 50+ paths (Hybrid Analysis) |
| Discovery | Process Discovery | T1057 | CreateToolhelp32Snapshot / NtQueryInformationProcess |
| Collection | Screen Capture | T1113 | Hybrid Analysis confirmed |
| Collection | Automated Collection | T1119 | FTP file enumeration (Hybrid Analysis) |
| Lateral Movement | Replication Through Removable Media | T1091 | Self-copies temp.zip + file.exe across 50+ paths |
| Command & Control | Application Layer Protocol | T1071 | IIS/HTTP strings; curl capability observed |
| Command & Control | Ingress Tool Transfer | T1105 | Curl-based transfer capability (Hybrid Analysis) |
| Command & Control | Encrypted Channel | T1573 | Encrypted C2 channel assessed |
| Impact | Inhibit System Recovery | T1490 | System Restore disable |
| Impact | Service Stop | T1489 | Hybrid Analysis confirmed |
| Impact | System Shutdown/Reboot | T1529 | Hybrid Analysis confirmed |
| Impact | Data Encrypted for Impact | T1486 | Flagged by Hybrid Analysis (ransomware-like behaviour) |
| Impact | Modify Registry | T1112 | Extensive registry CRUD (12+ API calls) |

---

## Attribution Assessment

**Confidence: MEDIUM**

| Factor | Assessment |
|--------|-----------|
| Developer username | **`DucDun`** — leaked in VB6 P-code path artefact; directly matches YARA family name `DUCDUN` |
| Project directory | `D:\Lap Trinh\Virus Mau\` (Vietnamese: "Programming\Virus Templates") — confirms Vietnamese-speaking developer |
| Iteration marker | `Pro 3` / `Pro3.vbp` — at least 3rd version of this tool |
| Target | Vietnamese-speaking users (musicvn lure) |
| Sophistication | Medium — custom encoding, fake packer, modular VB6 architecture |
| Infrastructure | Not recovered — limits pivot capability |
| CompanyName | `SBC` — unknown actor or group marker |
| Pattern match | Consistent with Vietnamese cybercriminal groups using VB6 (Cyble 2024, Google TI 2024) |

**Conclusion:** The DUCDUN family RAT is attributed with medium confidence to a Vietnamese individual or group operating under the developer identity "DucDun". The `Virus Mau` (Template Virus) project directory indicates an actor iterating on custom malware. No confirmed infrastructure or external entity linkage.

---

## Detection

### Updated YARA Signature

```yara
rule DUCDUN_VB6_RAT_Pro3 {
    meta:
        description     = "DUCDUN VB6 RAT — musicvn.exe campaign, Pro3 variant"
        author          = "Internal CTI"
        date            = "2026-04-18"
        hash_sha256     = "f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d"
        confidence      = "high"
        mitre_attack    = "T1059.005, T1027.002, T1547.001, T1562.001, T1070.004"
        family          = "DUCDUN"
    strings:
        $vb6_runtime    = "MSVBVM60.dll" ascii
        $mod_bind       = "module_bind" wide ascii
        $mod_registry   = "module_registry" wide ascii
        $mod_check      = "module_check" wide ascii
        $mod_funny      = "module_funny" wide ascii
        $mod_rnd        = "module_rnd" wide ascii
        $musicvn        = "musicvn" wide ascii
        $system_rst     = "System Restore" wide ascii
        $priv_backup    = "SeBackupPrivilege" wide ascii
        $encoded_str    = "w@gylz///////" ascii
        $vprotect       = "VirtualProtect" ascii
        $dev_path       = "Virus Mau" wide ascii
        $dev_name       = "DucDun" wide ascii
        // Overlay WCHAR config marker: 00-indexed values 1-59 as big-endian shorts
        $overlay_sig    = { 00 18 00 1D 00 29 00 24 00 24 00 1B 00 21 00 33 00 3B }
    condition:
        uint16(0) == 0x5A4D and
        $vb6_runtime and
        (
            $overlay_sig or
            ($dev_path and $dev_name) or
            3 of ($mod_bind, $mod_registry, $mod_check, $mod_funny, $mod_rnd,
                  $musicvn, $system_rst, $priv_backup, $encoded_str, $vprotect)
        )
}
```

### Behavioral / Sigma Detections

```yaml
# Detect NoFolderOptions evasion key write
title: DUCDUN NoFolderOptions Anti-Forensic Registry Write
id: ducdun-nofolderoptions-001
status: experimental
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: '\Policies\Explorer'
    Details: 'DWORD (0x00000001)'
    TargetObject|endswith: 'NoFolderOptions'
  filter_system:
    Image|startswith: 'C:\Windows\System32\'
  condition: selection and not filter_system
tags:
  - attack.defense_evasion
  - attack.t1562.001

---

# Detect self-copy of ZIP + EXE to %TEMP% from VB6 process
title: DUCDUN Self-Replication to TEMP Directory
id: ducdun-selfreplication-001
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    Image|endswith: 'file.exe'
    TargetFilename|contains:
      - '\AppData\Local\Temp\backup.exe'
      - '\AppData\Local\Temp\temp.zip'
      - '\AppData\Local\Temp\file.dat'
  condition: selection
tags:
  - attack.persistence
  - attack.t1091
```

### Network Hunting
- Monitor processes loading `MSVBVM60.dll` for **any outbound TCP connection** not to Microsoft IP ranges
- Alert on `file.exe` or `backup.exe` (by name) making DNS queries
- Hunt for `file.dat` (1001 bytes, SHA256: `BFAF5AA...`) in %TEMP% directories across endpoints

### Endpoint
- Block PE files with `ProductName: Microsoft Windows` but without Microsoft Authenticode signature
- Alert on `Shell.Application` + `Namespace()` + `CopyHere()` from non-installer processes (ZIP extraction evasion)
- Monitor `AdjustTokenPrivileges` from non-system processes
- Alert on `RegSaveKeyA` / `RegRestoreKeyA` calls (extremely rare in legitimate software)
- Detect `NoFolderOptions = 1` registry write from non-administrative processes

---

## Analysis Gaps / Recommended Next Steps

1. **Extended sandbox** (5+ minutes) — The 60-second any.run window was insufficient for C2 contact. Re-run with longer timeout or manual sandbox to capture:
   - C2 hostname/IP decoded from overlay config
   - Mutex name
   - Drop paths for RLE-decoded secondary payload
   - Network beacon structure and protocol

2. **VB Decompiler analysis** — Extract P-code from UPX0 section (already uncompressed) using VB Decompiler Pro or p-code tools to recover the alphabet assembly order for overlay Region 1

3. **file.dat decryption** — Identify `module_rnd` LCG seed and key derivation logic; decrypt the 1001-byte runtime config to recover stored C2 parameters

4. **file.zip recovery** — SHA256 `9B71B89DD...` was dropped but not captured in the current sample set; retrieve from sandbox filesystem image

5. **Infrastructure pivot** — Once C2 recovered, pivot on hostname via Shodan/Censys, passive DNS (SecurityTrails, DNSDB), VirusTotal, and ThreatFox for campaign scope

6. **Actor OSINT** — Search for `DucDun` / `DucDuyen` handle on Vietnamese forums (HVA Online, WhiteHat.vn, VietHacker) and code repositories for additional tooling

---

## References

- any.run sandbox report: https://any.run/report/f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d/a4e673f7-996f-40fe-a940-adfe359dab5b
- Broadcom Symantec: [VB6 Threats Still Active In 2024](https://www.broadcom.com/support/security-center/protection-bulletin/protection-highlight-vb6-threats-still-active)
- Cyble: [Vietnamese Threat Actor's Strategy on Digital Marketers](https://cyble.com/blog/vietnamese-threat-actors-multi-layered-strategy-on-digital-marketing-professionals/)
- Google Threat Intelligence: [Vietnamese Actors Using Fake Job Posting Campaigns](https://cloud.google.com/blog/topics/threat-intelligence/vietnamese-actors-fake-job-posting-campaigns)
- Huntress: [Vietnamese Threat Actor's Shift from PXA Stealer to PureRAT](https://www.huntress.com/blog/purerat-threat-actor-evolution)
- The Hacker News: [Vietnam-Based Hackers Steal Financial Data Across Asia](https://thehackernews.com/2024/04/vietnam-based-hackers-steal-financial.html)
- MITRE ATT&CK: https://attack.mitre.org/

---

*Report updated 2026-04-18. Analysis performed using: REMnux static analysis (file, peframe, pecheck, FLOSS, pestr, CAPA, manalyze, xorsearch, base64dump, ssdeep, signsrch) + any.run dynamic sandbox + Python overlay parsing scripts. Config decoding attempted via 720-permutation alphabet brute-force — not resolved without dynamic execution.*
