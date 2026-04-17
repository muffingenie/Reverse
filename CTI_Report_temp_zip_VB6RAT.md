# CTI Report: VB6 RAT/Dropper — musicvn.exe Campaign
**Classification:** TLP:AMBER  
**Date:** 2026-04-17  
**Analyst:** REMnux Static Analysis + OSINT  
**Confidence:** Medium (static analysis only; no sandbox execution)

---

## Executive Summary

A ZIP archive (`temp.zip`) was submitted for analysis containing a single PE32 binary (`file.exe`). Static analysis reveals a custom Visual Basic 6 (VB6) compiled dropper/RAT masquerading as a Vietnamese music player application (`musicvn.exe`). The binary uses a modified UPX packer to defeat automated unpacking, carries a 339KB overlay with a multi-stage custom encoding scheme (WCHAR-encoded config + RLE-encoded secondary payload), and implements a wide range of malicious capabilities including privilege escalation, persistent registry manipulation, System Restore disabling, and network communication. The sample has **no public hash match** across available threat intelligence databases, suggesting it is either novel or deliberately kept off scanning platforms.

**Verdict:** **Malicious — Custom VB6 RAT/Dropper** (high confidence)  
**Target:** Vietnamese-speaking users (musicvn lure)  
**Attribution:** Unknown; consistent with Vietnamese-nexus threat actor patterns (medium confidence)

---

## Sample Identification

| Property | Value |
|----------|-------|
| Container | `temp.zip` (32,854 bytes, no password) |
| Extracted | `file.exe` |
| File Type | PE32 executable (GUI), Intel i386, UPX-packed, VB6 |
| SHA256 | `f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d` |
| SHA1 | `081344b4dbe0844201196fb6836f4ae751f5b23a` |
| MD5 | `2da285b6da2e4848042b79011f56f291` |
| Size | 458,907 bytes |
| ssdeep | `768:CpQNwC3BESe4Vqth+0V5vKPyLylze70wi3BEmHP:CeT7BVwxfvLFwjRHP` |
| imphash | `af68cbb94282611291edeece0079bc64` |
| Public hash match | **None found** |

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
`Tue Jan 6 04:02:14 2009 UTC` — **Forged.** VB6 runtime `MSVBVM60.dll` was not broadly available in 2009 in the manner implied; timestamp is a deliberate anti-forensic measure consistent with toolkits that scrub or backdated timestamps.

### Section Layout

| Section | VA | Raw Size | Entropy | Flags | Assessment |
|---------|----|----------|---------|-------|-----------|
| UPX0 | 0x1000 | 0x10000 | 3.28 | R/W/X | UPX decompress target — all W+X suspicious |
| UPX1 | 0x11000 | 0x4000 | 4.30 | R/W/X | Compressed VB6 P-code + payload |
| .rsrc | 0x15000 | 0x6000 | 4.13 | R/W/X | Resources (icons, version info) — marked executable |
| .pb | 0x1B000 | 0x400 | 1.31 | R/W/X | Import table + VB6 P-code body |

All four sections carry `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` — a strong indicator of self-modifying packed code. Only `MSVBVM60.dll` is imported (minimal IAT surface for defense evasion).

### Overlay (Primary Carrier)

| Property | Value |
|----------|-------|
| Start offset | 0x1B400 (111,616 bytes) |
| Size | 347,291 bytes (75.7% of total file) |
| Overall entropy | 4.59 bits/byte |
| SHA256 | `746913436e828b525b72d686e16fcf649c12a772cce1cf06e5c03aac98f02fd4` |
| MD5 | `a2baac9ad6b69edd8d127799e10baa02` |

The overlay dominates the binary. Its multi-region structure is detailed in the **Payload Encoding** section below.

---

## Packer Analysis

The binary uses **UPX with a deliberately modified header** to prevent automated unpacking (`upx -d` fails). This is a well-documented anti-analysis technique where the UPX magic bytes or decompressor stub are patched post-packing to defeat `upx --decompress`. Standard tools (`upx-decompress`, `1768.py`) all fail on this sample.

CAPA detects:
- `packed with UPX` (anti-analysis/packer/upx)
- `compiled from Visual Basic` (compiler/vb)

**Note:** CAPA warns it cannot fully analyze VB6 P-code and recommends VB Decompiler for further static analysis. Only 2 functions were identified (vs. typical hundreds) — the binary is effectively opaque to conventional static CFG analysis.

---

## VB6 Project Structure

FLOSS extracted 407 static strings including VB6 project metadata. The project is well-structured with **dedicated functional modules**, indicating a custom-developed tool rather than commodity malware:

| Module | Assessed Function |
|--------|------------------|
| `frm_main` | Main GUI form (hidden window) |
| `class_main` | Core controller class |
| `module_main` | Entry point, orchestration |
| `module_bind` | **Network socket binding / C2 communication** |
| `module_rnd` | Randomization / key generation / crypto |
| `module_registry` | **Registry persistence operations** |
| `module_until` | Loop/timer control (beacon interval) |
| `module_path` | Filesystem path resolution |
| `module_check` | **AV/sandbox environment detection** |
| `module_funny` | Social engineering / decoy content |

The presence of `module_bind` strongly suggests direct TCP/UDP socket binding (not WinHTTP), while `module_until` likely controls C2 beacon timing.

---

## Resolved APIs (Behavioral Indicators)

APIs were identified from FLOSS static string extraction (VB6 P-code includes function names as embedded strings for late binding):

### Privilege Escalation
```
AdjustTokenPrivileges    OpenProcessToken    GetCurrentProcess
LookupPrivilegeValueA    SeRestorePrivilege  SeBackupPrivilege
```
The combination of `SeBackupPrivilege` + `SeRestorePrivilege` + `RegSaveKeyA` + `RegRestoreKeyA` enables **offline registry hive manipulation** — the malware can save the entire `HKLM\SAM` or `HKLM\SYSTEM` hive to disk, extract credential hashes, then restore it. This is a known lateral movement technique.

### Registry Manipulation
```
RegSetValueExA    RegQueryValueExA    RegOpenKeyExA    RegDeleteValueA
RegDeleteKeyA     RegCreateKeyExA     RegCloseKey      RegSaveKeyA
RegRestoreKeyA    RegEnumKeyExA       RegCreateKeyA
```
Extensive — covers full CRUD lifecycle including hive-level save/restore. Persistence, config storage, and credential theft are all possible.

### Process / Memory
```
VirtualProtect    CreateMutexA    ReleaseMutex    CloseHandle
ExitProcess       ExitWindowsEx   GetFileAttributesA
```
`VirtualProtect` is used to make memory regions executable — consistent with staging a shellcode payload decoded from the overlay at runtime.

`CreateMutexA` / `ReleaseMutex` — anti-double-execution mutex.

### Window Enumeration
```
FindWindowA    FindWindowExA    SendMessageA
PostMessageA   GetWindowTextLengthA
```
Used for AV/sandbox window detection (`module_check`), or to interact with and control other running processes.

### COM Objects
```
Scripting.FileSystemObject    CreateTextFile    Shell.Application
```
File creation and shell execution via COM — commonly used to drop additional payloads or scripts without direct Win32 API calls, evading some monitoring.

---

## Key Static Strings

| String | Significance |
|--------|-------------|
| `temp.zip` | Self-referential — binary is aware of its own container; may re-drop/re-spread |
| `System Restore` | Disabling Windows System Restore (T1490 — Inhibit System Recovery) |
| `Logon User Name` | Victim profiling — enumerating logged-on user |
| `Hidden` | Window/file hiding attribute |
| `backup` | Data exfiltration or local backup staging |
| `w@gylz///////` | Appears **twice** — encoded string, possibly an obfuscated URL or C2 identifier |
| `Shell.Application` | COM-based shell execution |
| `Scripting.FileSystemObject` | File write operations |
| `VBA6.DLL` | VB6 runtime reference |

**Registry paths accessed:**
```
Software\Microsoft\Windows\CurrentVersion\Explorer
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
Software\Microsoft\Windows\CurrentVersion\Explorer\Streams
```
These are Explorer shell settings — the malware likely modifies folder view settings to hide files (`Hidden` attribute) or disable security-relevant Explorer policies.

---

## Payload Encoding Analysis

The 347KB overlay contains three distinct regions:

### Region 1: Encoded Configuration (Bytes 0x000–0x18E)
- 199 WCHAR values stored as little-endian `00 XX` pairs
- Value range: `0x0001–0x003a` (1–58 decimal) — a 58-character encoded alphabet
- This is consistent with an encoded **C2 configuration string** (host, port, key, mutex name)
- No single-byte XOR key successfully decodes to printable ASCII; a custom multi-byte transform or keyed substitution cipher is used
- Decoding requires the runtime key embedded in the VB6 P-code (inaccessible without unpacking)

### Region 2: Null Padding (Bytes 0x18F–0x1DFFF)
- ~123KB of null bytes — runtime workspace, zeroed until populated on execution

### Region 3: RLE-Encoded Secondary Payload (Bytes 0x1E000–end)
- 224,411 bytes structured as **monotonic runs** of identical byte values
- Each unique byte value appears exactly once as a contiguous run (one run per symbol)
- Run-length decoded output: **28,051 bytes** of actual payload content
- Decoded byte distribution matches **x86 PE opcode frequency patterns** — the decoded data is likely a second-stage executable or shellcode
- Low entropy across the encoded form (0.5–2.5 bits/byte) confirms simple run-encoding rather than high-entropy encryption

The RLE + WCHAR encoding scheme is bespoke and not matched to any known public packer format, indicating **custom-developed tooling**.

---

## Behavioral Assessment

### Execution Flow (Assessed)
```
1. temp.zip delivered via phishing / social engineering
2. User extracts file.exe (lured as Vietnamese music player)
3. file.exe executes; VB6 runtime (MSVBVM60.dll) loads
4. Modified UPX stub decodes VB6 P-code into memory
5. module_check: AV/sandbox detection via FindWindowA + GetFileAttributesA
6. CreateMutexA: anti-double-execution mutex
7. module_rnd: key derivation for overlay decoding
8. Overlay config decoded → C2 host/port/mutex recovered
9. module_registry: HKCU Run key or COM hijack persistence
10. AdjustTokenPrivileges (SeBackupPrivilege) → registry hive access
11. System Restore disabled (inhibit recovery)
12. Shell.Application / FSO: secondary payload dropped + executed
13. VirtualProtect: overlay shellcode marked executable
14. module_bind: beacon loop to C2 (TCP socket bind)
15. module_until: sleep interval between beacons
16. module_funny: decoy content displayed (musicvn lure)
```

### Persistence Mechanisms (Assessed)
- **Registry Run key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (assessed via module_registry + RegSetValueExA)
- **COM abuse**: Possible COM object hijack via Explorer policies path
- **Registry hive manipulation**: SeBackupPrivilege + RegSaveKeyA — advanced persistence via saved registry blobs

### Defense Evasion
- Modified UPX header (defeats `upx -d`, `peframe`, `1768.py`)
- Forged version metadata (ProductName: Microsoft Windows)
- Forged compile timestamp (2009)
- VB6 P-code (defeats most static disassemblers / CAPA)
- WCHAR + RLE custom encoding (defeats most string extractors)
- COM object usage (avoids direct suspicious API calls)
- `module_check`: active sandbox detection

---

## Indicators of Compromise (IOCs)

### File Hashes
| Type | Value |
|------|-------|
| SHA256 (zip) | `[not computed — see file.exe]` |
| SHA256 (file.exe) | `f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d` |
| SHA1 (file.exe) | `081344b4dbe0844201196fb6836f4ae751f5b23a` |
| MD5 (file.exe) | `2da285b6da2e4848042b79011f56f291` |
| SHA256 (overlay) | `746913436e828b525b72d686e16fcf649c12a772cce1cf06e5c03aac98f02fd4` |
| SHA256 (PE without overlay) | `92f55f1a3a17012bc6fab14bcb87d4fcd995e3ccd435b19ee5a1bffcc662d12f` |
| imphash | `af68cbb94282611291edeece0079bc64` |
| ssdeep | `768:CpQNwC3BESe4Vqth+0V5vKPyLylze70wi3BEmHP:CeT7BVwxfvLFwjRHP` |

### File System
| Indicator | Value |
|-----------|-------|
| Original filename | `musicvn.exe` |
| Container | `temp.zip` |
| Decoy | Vietnamese music application |
| Suspected drop path | Unknown — runtime decoded from overlay config |

### Network
| Indicator | Value |
|-----------|-------|
| C2 host | **Unknown** — encoded in overlay Region 1 (not recovered statically) |
| C2 port | **Unknown** — encoded in overlay config |
| Protocol | TCP socket bind (module_bind), assessed raw socket |

### Registry
| Path | Operation | Purpose |
|------|-----------|---------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Write (assessed) | Persistence |
| `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | Read/Write | Hide files |
| `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | Read/Write | Policy bypass |

### Behavioral / Runtime
| Indicator | Value |
|-----------|-------|
| Mutex | Unknown — decoded at runtime |
| Privilege | SeBackupPrivilege, SeRestorePrivilege |
| COM objects | Scripting.FileSystemObject, Shell.Application |
| Encoded string | `w@gylz///////` (purpose unknown — possible C2 path fragment) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | VB6 compiled binary |
| Execution | Native API | T1106 | VirtualProtect, CreateMutexA |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | module_registry, RegSetValueExA |
| Privilege Escalation | Access Token Manipulation | T1134 | AdjustTokenPrivileges, OpenProcessToken |
| Defense Evasion | Obfuscated Files or Information: Software Packing | T1027.002 | Modified UPX header |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | WCHAR+RLE overlay encoding |
| Defense Evasion | Masquerading: Match Legitimate Name/Location | T1036.004 | musicvn.exe / ProductName: Microsoft Windows |
| Defense Evasion | Indicator Removal | T1070 | RegDeleteKeyA, RegDeleteValueA |
| Discovery | Security Software Discovery | T1518.001 | module_check, FindWindowA |
| Discovery | System Information Discovery | T1082 | Logon User Name enumeration |
| Collection | Archive Collected Data | T1560 | backup module |
| Command & Control | Non-Standard Port | T1571 | module_bind (assessed raw socket) |
| Impact | Inhibit System Recovery | T1490 | System Restore disable |
| Impact | Modify Registry | T1112 | Extensive registry CRUD |

---

## Attribution Assessment

**Confidence: LOW-MEDIUM**

| Factor | Assessment |
|--------|-----------|
| Target language | Vietnamese (musicvn lure, primary indicator) |
| Self-targeting | Possible — Vietnamese threat actors historically target co-nationals |
| False flag | Cannot be excluded — no corroborating infrastructure IOCs |
| Sophistication | Medium — custom encoding, modified packer, modular VB6 architecture |
| Tooling | Custom-developed (no public match to known RAT builders) |
| CompanyName "SBC" | Unknown actor marker; no public attribution |
| Comparison | Consistent with Vietnamese-nexus threat actors using commodity RATs evolved into custom tooling (e.g., PXA Stealer → PureRAT evolution documented by Huntress 2025) |

**No confirmed attribution.** The sample shares behavioral patterns (VB6, lure-based delivery, registry manipulation) with Vietnamese cybercriminal groups documented by Cyble, Google Threat Intelligence, and HackerNews (April 2024), but no direct malware-family linkage is established.

---

## Detection Recommendations

### YARA Signature (Draft)
```yara
rule VB6_musicvn_RAT {
    meta:
        description = "VB6 RAT musicvn.exe campaign — UPX-packed dropper with encoded overlay"
        date = "2026-04-17"
        hash_sha256 = "f8bbe59a29302484ef064b7154d596cc27444dcc017702e88c9bafe8a15c5a2d"
        confidence = "medium"
    strings:
        $vb6_runtime  = "MSVBVM60.dll" ascii
        $mod_bind     = "module_bind" wide ascii
        $mod_registry = "module_registry" wide ascii
        $mod_check    = "module_check" wide ascii
        $mod_funny    = "module_funny" wide ascii
        $musicvn      = "musicvn" wide ascii
        $system_rst   = "System Restore" wide ascii
        $priv_backup  = "SeBackupPrivilege" wide ascii
        $encoded_str  = "w@gylz///////" ascii
        $vprotect     = "VirtualProtect" ascii
    condition:
        uint16(0) == 0x5A4D and
        $vb6_runtime and
        3 of ($mod_bind, $mod_registry, $mod_check, $mod_funny, $musicvn,
              $system_rst, $priv_backup, $encoded_str, $vprotect)
}
```

### Sigma / Behavioral Detection
```yaml
# Detect privilege token abuse followed by registry hive save
title: Registry Hive Theft via SeBackupPrivilege
detection:
  selection:
    EventID: 4673
    PrivilegeName|contains:
      - 'SeBackupPrivilege'
      - 'SeRestorePrivilege'
  condition: selection
```

### Network
- Monitor for outbound TCP connections from `MSVBVM60.dll`-dependent processes to non-standard ports
- Alert on any process spawned by `file.exe`, `musicvn.exe`, or processes loading `MSVBVM60.dll` making network connections

### Endpoint
- Block execution of PE files with `ProductName: Microsoft Windows` but not signed by Microsoft
- Alert on `Scripting.FileSystemObject` + `Shell.Application` COM instantiation from VB6 processes
- Monitor `AdjustTokenPrivileges` calls from non-system processes
- Alert on `RegSaveKeyA` / `RegRestoreKeyA` calls (rare in legitimate software)

---

## Recommended Next Steps

1. **Dynamic analysis** — Execute in isolated sandbox to recover:
   - C2 hostname/IP and port from decoded overlay config
   - Mutex name
   - Drop paths for secondary payload
   - Network beacon structure

2. **VB Decompiler analysis** — Decompile the UPX-unpacked binary (via memory dump or manual stub patch) using VB Decompiler Pro or p-code decompiler to recover full source logic

3. **Overlay decryption** — Identify the runtime key in VB6 P-code used to decode the 199-WCHAR config block in the overlay; 58-character alphabet suggests a custom substitution or Vigenère-style cipher

4. **Infrastructure pivot** — Once C2 decoded, pivot on IP/domain for related campaigns, passive DNS, certificate history

5. **VirusTotal submission** — Submit both `temp.zip` and `file.exe` for multi-AV coverage and retrohunting correlation

6. **Sigma/YARA hunting** — Deploy draft YARA rule across email gateway, endpoint, and SIEM for retroactive detection

---

## References

- Broadcom Symantec: [Protection Highlight: VB6 Threats Still Active In 2024](https://www.broadcom.com/support/security-center/protection-bulletin/protection-highlight-vb6-threats-still-active) (Feb 2024)
- Cyble: [Vietnamese Threat Actor's Strategy on Digital Marketers](https://cyble.com/blog/vietnamese-threat-actors-multi-layered-strategy-on-digital-marketing-professionals/)
- Google Threat Intelligence: [Vietnamese Actors Using Fake Job Posting Campaigns](https://cloud.google.com/blog/topics/threat-intelligence/vietnamese-actors-fake-job-posting-campaigns)
- Huntress: [Vietnamese Threat Actor's Shift from PXA Stealer to PureRAT](https://www.huntress.com/blog/purerat-threat-actor-evolution)
- The Hacker News: [Vietnam-Based Hackers Steal Financial Data Across Asia](https://thehackernews.com/2024/04/vietnam-based-hackers-steal-financial.html)
- MITRE ATT&CK: https://attack.mitre.org/

---
note from Muffin: Assess with medium confidence that it is a plugX dropper

*Report generated from REMnux static analysis using: file, peframe, pecheck, pedump, portex, capa, floss, pestr, manalyze, exiftool, yara-rules, ssdeep, signsrch, base64dump, xorsearch — depth=deep. No dynamic execution performed.*
