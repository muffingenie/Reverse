# CTI Report: Mustang Panda PlugX — Arabic GCC Lure via BaiduNetdisk DLL Sideloading
**TLP:WHITE**  
**Date:** 2026-04-05  
**Analyst:** REMnux Static Analysis + Open-Source Intelligence  
**Confidence:** HIGH (kill chain, IOCs, tooling); MEDIUM (attribution to Mustang Panda)

---

## Executive Summary

A CHM-based malware delivery campaign targeting Persian Gulf (GCC) nations was identified, delivering a PlugX backdoor via a multi-stage DLL sideloading chain disguised as the legitimate Baidu NetDisk cloud storage application. The lure is an Arabic-language PDF document (`محضر ال.pdf`) created by "Abo Hasnah" on 2026-03-16, consistent with GCC-themed social engineering. Technical indicators, tooling, and the `YYYYMMDD@@@` RC4 date-keyed decryption pattern link this campaign with high confidence to a China-nexus actor and with medium confidence to **Mustang Panda (TA416)**, consistent with Zscaler ThreatLabz March 2026 reporting on "Weaponizing Conflict" Middle East campaigns.

---

## Sample Metadata

| Field | Value |
|-------|-------|
| Filename | `sample.chm` |
| File Type | MS Windows HtmlHelp Data (CHM v3) |
| SHA256 | `af8bf1848b06c3a4236b13b57f88e9c2744bc3c3db2adc91dcbf320862dcc032` |
| SHA1 | `971320c8fc9e663339988d3e95879653bbf3c1b2` |
| MD5 | `9abb71ae94aec7126993a44c9f40861b` |
| Size | 1,992,434 bytes |
| CHM Language Metadata | Chinese (Simplified) — actor artefact |
| Weaponization Date | 2026-03-16 (all internal timestamps) |

---

## Kill Chain

```
sample.chm
    │
    ├── $OBJINST  (CLSID: {4662DAAF-D393-11D0-9A56-00C04FB68BF7})
    │   └── Auto-exec on CHM open → runs 7S7CYJBX.lnk
    │
    ├── OAR6PBR → renamed → "محضر ال.pdf"  (Arabic decoy PDF, 9 pp.)
    │
    ├── 7S7CYJBX.lnk
    │   └── cmd.exe /c move OAR6PBR "محضر ال.pdf" & explorer "محضر ال.pdf"
    │       [Arabic lure displayed to victim; ZIP payload extracted in parallel]
    │
    └── 07TACBPR9  (ZIP)
        └── BaiduNetdisk\
            ├── ShellFolder.exe       ← legitimate signed Baidu binary (sideload host)
            ├── ShellFolderDepend.dll ← MALICIOUS loader (forged Tencent metadata)
            ├── Shelter.ex            ← RC4-encrypted PlugX shellcode payload
            └── [msvcp140.dll, vcruntime140.dll, api-ms-win-crt-*.dll]  (legitimate CRT)
                        │
                        ▼
            ShellFolder.exe calls _RigsterHook@0 from ShellFolderDepend.dll
                        │
                        ▼
            ShellFolderDepend.dll:
              1. Enumerates processes (AV/EDR check)
              2. Queries registry
              3. Reads Shelter.ex from working directory
              4. Decrypts Shelter.ex via RC4 (SystemFunction033, dynamically resolved)
                 Key: 20260316@@@ (date-keyed; pattern YYYYMMDD@@@)
              5. Allocates RWX memory, writes decrypted shellcode
              6. Creates thread → executes PlugX shellcode
              7. Sets persistence: HKCU\...\Run\BaiNetdisk → ShellFolder.exe --path a
                        │
                        ▼
            Shelter.ex (decrypted shellcode):
              - Position-independent, CFF + MBA obfuscated
              - Anti-disassembly junk byte at offset 0x00
              - GetPC trick (CALL $+5) at offset 0x2D
              - Secondary decryption stub at offset 0x18C5 decodes nested payload
              - Bootstraps full PlugX backdoor DLL in-memory
                        │
                        ▼
            PlugX backdoor (C2 over HTTPS + DoH)
              - C2: www.360printsol[.]com / 91.193.17[.]117:443
```

---

## Component Analysis

### 1. CHM Container (`sample.chm`)

| Property | Value |
|----------|-------|
| CHM Version | 3 |
| Language metadata | Chinese (Simplified) |
| Auto-exec mechanism | `$OBJINST` stream, CLSID `{4662DAAF-D393-11D0-9A56-00C04FB68BF7}` |
| Internal files | OAR6PBR (PDF decoy), 07TACBPR9 (ZIP), 7S7CYJBX.lnk, $OBJINST, #SYSTEM, #IDXHDR |

The `$OBJINST` stream encodes a CHM shortcut object. When the CHM is opened, Windows HTML Help renders `$OBJINST` and automatically executes the embedded LNK without any additional user interaction beyond opening the file. The `{4662DAAF-D393-11D0-9A56-00C04FB68BF7}` CLSID is the HTML Help shortcut auto-exec class.

**Anti-analysis note:** CHM language metadata is set to Chinese (Simplified) — inconsistent with the Arabic lure target audience and consistent with a China-nexus operator's development environment.

---

### 2. LNK Launcher (`7S7CYJBX.lnk`)

| Property | Value |
|----------|-------|
| Size | 431 bytes |
| ctime / atime / mtime | 2026-03-16 03:45:53 UTC (all identical) |
| Target | `%SystemRoot%\System32\cmd.exe` |
| Working directory | `%TEMP%` |

**Decoded Unicode command line (extracted from LNK StringData section):**
```
cmd.exe /c move OAR6PBR "محضر ال.pdf" & explorer "محضر ال.pdf"
```

The command renames the embedded PDF to an Arabic filename (`محضر ال.pdf` = "Minutes/Record of [...]"), opens it for the victim to view, and simultaneously the ZIP (07TACBPR9) is extracted to deliver the BaiduNetdisk sideloading kit.

---

### 3. Decoy PDF (`OAR6PBR` → `محضر ال.pdf`)

| Property | Value |
|----------|-------|
| Size | 812,944 bytes |
| PDF Version | 1.5 |
| Pages | 9 |
| Author | Abo Hasnah (Arabic personal name) |
| Creator / Producer | Microsoft® Word 2016 |
| Created / Modified | 2026-03-16 03:15:23 UTC |
| Language | en-US |
| Embedded scripts / JS | None (pdfid confirms: /JS=0, /OpenAction=0, /Launch=0) |

The decoy is a benign Arabic-language government document themed around GCC/Middle East conflict. No malicious PDF constructs. Used purely for social engineering to maintain victim credibility while payload executes in background.

---

### 4. ZIP Sideloading Kit (`07TACBPR9`)

| Filename | Size | SHA256 | Compiled | Notes |
|----------|------|--------|----------|-------|
| ShellFolder.exe | 35,552 | `18a5bcdde4b244274c646d59b04f21eb65e20334bb72a501562aab7aef06c902` | 2025-10-27 | Legitimate Baidu binary, Authenticode signed |
| ShellFolderDepend.dll | 1,161,728 | `216989f56970e3ea045773224e82b2afe78ed29e49df7d044d5a5992d622d881` | **2026-03-16 02:59:07** | **MALICIOUS loader** |
| Shelter.ex | 528,702 | `4f8cbb8e4595b0b158062b314678fad7da05202dccfa28604733ac1448a9025d` | **2026-03-16 11:45:52** | **RC4-encrypted PlugX shellcode** |
| msvcp140.dll | 439,608 | — | 2026-03-09 | Legitimate Microsoft CRT |
| vcruntime140.dll | 85,328 | — | 2026-03-09 | Legitimate Microsoft CRT |
| api-ms-win-crt-*.dll (×5) | various | — | 2026-03-09 | Legitimate Windows CRT stubs |

ZIP timestamps reveal two-phase assembly:
- **2026-03-09**: ShellFolder.exe and CRT DLLs staged (toolkit pre-positioning)
- **2026-03-16**: ShellFolderDepend.dll and Shelter.ex compiled and packaged (weaponization day)

---

### 5. Sideload Host (`ShellFolder.exe`)

| Property | Value |
|----------|-------|
| Type | PE32 Console (MSVC 2015, LTCG), Authenticode signed |
| PDB path | `H:\baidu\netdisk\pc-yunbrowser\output\ShellFolder.pdb` |
| Compiled | 2025-10-27 |
| Key import | `ShellFolderDepend.dll._RigsterHook@0` (Ordinal 0) |
| Key import | `ShellFolderDepend.dll._UnRigsterHook@0` (Ordinal 1) |

This is a legitimate Baidu NetDisk component. Its sole purpose in this attack is to serve as a signed binary that loads the malicious DLL. The export name typo "**Rigster**" (vs "Register") is a consistent actor artefact. Execution path: `ShellFolder.exe --path a` triggers the `_RigsterHook@0` code path.

---

### 6. Malicious Loader (`ShellFolderDepend.dll`)

| Property | Value |
|----------|-------|
| SHA256 | `216989f56970e3ea045773224e82b2afe78ed29e49df7d044d5a5992d622d881` |
| MD5 | `eba8acc9e751d06d0e49093d2a8f5e93` |
| imphash | `551af7f202e2768c63b16f27eadd2d27` |
| Type | PE32 DLL, Console, i386 |
| **Actual compiler** | **Borland C++ Builder Enterprise (Turbo Linker 5.0)** |
| Compiled | 2026-03-16 02:59:07 UTC |
| Size | 1,161,728 bytes |
| Sections | `.text` (entropy 6.56), `.data`, `.tls`, `.idata`, `.didata`, `.edata`, `.rsrc`, `.reloc` |

**Forged version resource (masquerading as Tencent):**

| Field | Forged Value |
|-------|-------------|
| CompanyName | Tencent Technology (Shenzhen) Company Limited |
| FileDescription | dlcore.dll |
| FileVersion | 1, 9, 656, 401 |
| InternalName | Tencentdl Module |
| OriginalFilename | dlcore.dll |
| LegalCopyright | Copyright © 2016 Tencent. All Rights Reserved. |

The DLL is compiled with **Borland C++ Builder** — incompatible with the claimed Tencent origin (Tencent uses MSVC). The metadata is entirely fabricated.

**Exports:**

| Name | Ordinal | RVA |
|------|---------|-----|
| `_RigsterHook@0` | 6 | `0x0000488C` |
| `_UnRigsterHook@0` | 7 | `0x00002B60` |
| `__dbk_fcall_wrapper` | 1 | `0x00001FD0` |
| `TMethodImplementationIntercept` | 2 | `0x000776C8` |
| (+ 3 Borland/Delphi RTL exports) | 3–5 | — |

**Key capabilities (CAPA confirmed):**

| ATT&CK | Capability | Evidence |
|--------|-----------|----------|
| T1027 | Stack-constructed obfuscated strings (2 matches) | CAPA, FLOSS |
| C0027.009 | **RC4 via PRGA** (4 function matches) | CAPA |
| C0026.002 | XOR data encoding (25 matches) | CAPA |
| T1057 | Process enumeration | `CreateToolhelp32Snapshot`, `Process32First/Next` |
| T1012 | Registry query | `RegOpenKeyExW`, `RegQueryValueExW` |
| T1614.001 | System language/locale discovery (11 matches) | CAPA |
| T1082 | System information discovery | CAPA |
| T1059 | Command interpreter invocation (`cmd.exe`) | static string |
| C0007 | RWX memory allocation | `VirtualAlloc` |
| C0038/C0054 | Thread create/resume | import table |
| C0047 | File deletion (anti-forensics) | CAPA |

**Dynamic API resolution (evasion):**

The DLL imports `GetProcAddress`, `LoadLibraryA`, `LoadLibraryW`, `LoadLibraryExW` and resolves `SystemFunction033` from `ADVAPI32.DLL` at runtime. `SystemFunction033` is the undocumented Windows RC4 primitive — resolving it dynamically avoids any static `CryptDecrypt` / `BCrypt` import signature and bypasses most import-table-based detections.

**RC4 key:** `20260316@@@` (11 bytes, constructed as a stack string at runtime)
- Pattern: `YYYYMMDD@@@` — date-keyed per weaponization date
- Confirmed by ThreatLabz for March 1 wave: `20260301@@@`
- Assessed for this March 16 wave: `20260316@@@`
- Decryption validated: applying RC4(`20260316@@@`) to `Shelter.ex` yields position-independent shellcode with documented CFF/MBA obfuscation profile

---

### 7. Encrypted PlugX Shellcode (`Shelter.ex`)

| Property | Value |
|----------|-------|
| SHA256 | `4f8cbb8e4595b0b158062b314678fad7da05202dccfa28604733ac1448a9025d` |
| Size | 528,702 bytes |
| Encrypted state | High-entropy binary blob (no magic bytes) |
| Encryption | RC4, key `20260316@@@`, via `SystemFunction033` |

**Decrypted shellcode layout:**

| Offset | Content |
|--------|---------|
| `0x00` | Anti-disassembly junk byte (`0x3B`) — confuses linear disassemblers |
| `0x01` | `EB 02` — JMP SHORT over 2 dead bytes, real execution begins at `0x05` |
| `0x05–0x2C` | CFF-flattened prologue: NOP-equivalents (`SUB ESI,0`; `OR CX,0`; `ADD CH,0`) |
| `0x2D` | `E8 00 00 00 00` — GetPC: CALL $+5 loads EIP for position-independence |
| `0x32–0x67` | Bootstrap setup, argument preparation |
| `0x68` | `E8 58 18 00 00` — CALL 0x18C5 (secondary decryption/decompression stub) |
| `0x6C+` | Nested payload: CFF+MBA-obfuscated PlugX loader, decrypted at runtime by stub at 0x18C5 |

The two-layer obfuscation (RC4 outer + CFF/MBA inner) prevents full static analysis. Complete PlugX behaviour is only recoverable in a controlled dynamic analysis environment. This obfuscation profile is consistent with ThreatLabz's description of the updated Mustang Panda toolset generation.

**Full RC4 key chain (open-source confirmed for March 1 wave; assessed for March 16 wave):**

| Stage | Key | Method | Source |
|-------|-----|--------|--------|
| Shelter.ex → shellcode | `20260301@@@` (March 1) / `20260316@@@` (March 16, assessed) | `SystemFunction033` | ThreatLabz confirmed / date-pattern extrapolation |
| PlugX config blob decryption | `qwedfgx202211` | Custom RC4 | ThreatLabz confirmed |
| PlugX C2 traffic encryption | `VD*1^N1OCLtAGM$U` | RC4 | ThreatLabz confirmed |

The config key `qwedfgx202211` is a known DOPLUGS-family fingerprint — ThreatLabz explicitly links this campaign to the DOPLUGS PlugX variant lineage via this key.

---

### 8. PlugX Core DLL (Statically Extracted)

Full payload chain resolved via static analysis without emulation:

| Stage | Algorithm | Input | Output |
|-------|-----------|-------|--------|
| 1 | RC4 (`20260316@@@`) | `Shelter.ex` (528,702 B) | `shelter_dec.bin` — position-independent shellcode |
| 2 | LCG XOR (seed `0xC56DD7EA`) | Bytes `0x18E2–0x7E0CA` (509,928 B) | LZNT1-compressed blob with 16-byte header |
| 3 | LZNT1 decompression | Compressed payload (509,912 B) | PlugX core DLL (715,264 B) |

**LCG formula (stage 2):** `key = (seed + (seed >> 3) + 0x13233366) & 0xFFFFFFFF` (advances per byte; low byte = XOR key byte)

**Compressed blob header (post-LCG, offset 0):**

| Field | Value |
|-------|-------|
| Magic | `0x585CABA7` |
| Seed/flag | `0xC56DD7EA` |
| Decompressed size | `0x000AEA00` (715,264 bytes) |
| Compressed size | `0x0007C7D8` (509,912 bytes) |

**Extracted PlugX core (`plugx_core_chm.bin`):**

| Property | Value |
|----------|-------|
| SHA256 | `ef7a813124fd19d11bb5d944cb95779f5fe09ff5a18c26399002759d4b0d66e7` |
| MD5 | `43622a9b16021a5fb053e89ea5cb2c4c` |
| Size | 715,264 bytes |
| Architecture | x86 (PE32), ImageBase `0x00000200` |
| PE timestamp | `0x00000000` (zeroed — anti-forensics) |
| AddressOfEntryPoint | `0x0000D800` |
| SizeOfImage | `0x000B7000` (749,568 bytes) |
| Sections | 6: `.text` (6.94 ent), `.rdata` (5.47), `.data` (0.92 — mostly zero), `.00cfg`, `.voltbl`, `.reloc` |
| DOS header | Non-standard (begins `"XseAJbaL..."` — CFF-obfuscated stub); COFF header valid at e_lfanew+4 |
| Strings | All API names and config strings encoded via CFF/MBA; no plaintext IOCs recoverable statically |

**Config blob:** Located at `shelter_dec.bin[0x6D:0x18C5]` (6,232 bytes, seed `0x9FC094F6`). Encryption uses a 4-state PRNG + per-field RC4 (`qwedfgx202211`). PRNG constants are variant-specific and not fully recovered from static analysis of this sample; IOCs sourced from ThreatLabz sandbox telemetry are used in the C2 section below.

---

## Persistence

```
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value:     BaiNetdisk
Data:      C:\Users\<victim>\AppData\Roaming\BaiduNetdisk\ShellFolder.exe --path a
```

On next logon, `ShellFolder.exe` executes, calls `_RigsterHook@0`, and restarts the full shellcode loading chain.

---

## C2 Infrastructure

| IOC | Type | Notes |
|-----|------|-------|
| `www.360printsol[.]com` | Domain | C2 + CHM distribution staging |
| `91.193.17[.]117` | IPv4 | Resolved IP of 360printsol[.]com |
| `443/TCP` | Port | HTTPS C2 channel |
| `hxxps://www.360printsol[.]com/2026/alfadhalah/thumbnail?img=index.png` | URL | CHM distribution URL (ThreatLabz) |

**Protocol:** HTTPS + DNS-over-HTTPS (DoH) for C2 channel, evading DNS-layer network monitoring.

The domain `360printsol[.]com` mimics the "360" Chinese security software brand — consistent with Mustang Panda's use of China-themed domain names.

---

## Indicators of Compromise

### File Hashes

| File | SHA256 | MD5 |
|------|--------|-----|
| `sample.chm` | `af8bf1848b06c3a4236b13b57f88e9c2744bc3c3db2adc91dcbf320862dcc032` | `9abb71ae94aec7126993a44c9f40861b` |
| `ShellFolderDepend.dll` | `216989f56970e3ea045773224e82b2afe78ed29e49df7d044d5a5992d622d881` | `eba8acc9e751d06d0e49093d2a8f5e93` |
| `Shelter.ex` | `4f8cbb8e4595b0b158062b314678fad7da05202dccfa28604733ac1448a9025d` | — |
| `ShellFolder.exe` | `18a5bcdde4b244274c646d59b04f21eb65e20334bb72a501562aab7aef06c902` | `7d66f747a787314ea3b9408e3a019421` |
| `plugx_core_chm.bin` (extracted) | `ef7a813124fd19d11bb5d944cb95779f5fe09ff5a18c26399002759d4b0d66e7` | `43622a9b16021a5fb053e89ea5cb2c4c` |

### Fuzzy Hashes (ssdeep)

| File | ssdeep |
|------|--------|
| `sample.chm` | `49152:krqCL+seQ0naiq/kqB85LyhV0N8042Ty2gtuvVq5k2nee:krq2eQ0a5/8QdyS8Akk` |
| `ShellFolderDepend.dll` | `24576:FDMUAngFozNckjKRbbf+8m3SoQPabMRmt4:bFoR3jKRTWSx6MRmm` |
| `ShellFolder.exe` | `768:YO2HmR+Zc8EbkVQ67stoNnbLEYi6wF5Yi6XmVWV9+kC:Yzc1kVQntEn876wD76XmQk` |
| `Shelter.ex` | `12288:KQJF79/QBcSXecmrrBRiynHBkkSKWJKraC/zI6H3XvtE:JJf/gpeiyhkklDrnZE` |

### Network IOCs

| IOC | Type |
|-----|------|
| `www.360printsol[.]com` | Domain (C2) |
| `91.193.17[.]117` | IPv4 (C2) |
| `443/TCP` | Port (HTTPS C2) |
| `hxxps://www.360printsol[.]com/2026/alfadhalah/thumbnail?img=index.png` | Distribution URL |

### Host-Based IOCs

| Type | Value |
|------|-------|
| Registry (persistence) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BaiNetdisk` |
| Install path | `%APPDATA%\BaiduNetdisk\` |
| RC4 decryption key | `20260316@@@` (Shelter.ex) |
| CHM auto-exec CLSID | `{4662DAAF-D393-11D0-9A56-00C04FB68BF7}` |
| DLL export (typo IOC) | `_RigsterHook@0` |
| DLL imphash | `551af7f202e2768c63b16f27eadd2d27` |
| PDF author | `Abo Hasnah` |
| PDF creation time | `2026-03-16 03:15:23 UTC` |
| LNK compile time | `2026-03-16 03:45:53 UTC` |
| DLL compile time | `2026-03-16 02:59:07 UTC` |
| Shelter.ex compile time | `2026-03-16 11:45:52 UTC` |

---

## MITRE ATT&CK Mapping

| ID | Technique | Component |
|----|-----------|-----------|
| T1566.001 | Phishing: Spearphishing Attachment | CHM delivered as attachment |
| T1204.002 | User Execution: Malicious File | Victim opens CHM |
| T1218.001 | Signed Binary Proxy Execution: CHM | Auto-exec via `$OBJINST` |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | `HKCU\...\Run\BaiNetdisk` |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | ShellFolder.exe → ShellFolderDepend.dll |
| T1140 | Deobfuscate/Decode Files | RC4 `SystemFunction033` decrypt of Shelter.ex |
| T1059.003 | Command and Scripting Interpreter: CMD | LNK → cmd.exe |
| T1036.005 | Masquerading: Match Legitimate Name/Location | Forged Tencent metadata; BaiduNetdisk path |
| T1027.002 | Obfuscated Files or Information: Packing | CFF+MBA obfuscation in shellcode |
| T1027.005 | Indicator Removal from Tools | Dynamic API resolution via GetProcAddress |
| T1055 | Process Injection | Shellcode in VirtualAlloc'd RWX region + CreateThread |
| T1057 | Process Discovery | Process enumeration (AV/EDR check) |
| T1012 | Query Registry | Registry reads during execution |
| T1082 | System Information Discovery | OS version, disk size checks |
| T1614.001 | System Language Discovery | 11 locale/geofencing checks (CFF-obfuscated) |
| T1071.001 | Application Layer Protocol: Web | HTTPS C2 on port 443 |
| T1071.004 | Application Layer Protocol: DNS | DNS-over-HTTPS (DoH) C2 evasion |

---

## Attribution Assessment

**Actor:** China-nexus threat actor  
**Cluster:** Mustang Panda (TA416) — **MEDIUM CONFIDENCE**

| Evidence | Weight |
|----------|--------|
| BaiduNetdisk DLL sideloading kit (ShellFolder.exe + ShellFolderDepend.dll + Shelter.ex) | HIGH — Mustang Panda signature since mid-2024 |
| `YYYYMMDD@@@` date-keyed RC4 pattern | HIGH — Mustang Panda-specific, documented by ThreatLabz |
| CHM language metadata = Chinese (Simplified) on Arabic-lure file | HIGH — consistent operational artefact |
| `_RigsterHook@0` export name typo | MEDIUM — consistent cross-sample artefact |
| CFF + MBA shellcode obfuscation | MEDIUM — matches updated Mustang Panda toolset profile |
| `360printsol[.]com` China-themed domain | MEDIUM — consistent with Mustang Panda naming pattern |
| Rapid weaponization of GCC/Arabic conflict theme | MEDIUM — consistent operational tempo |
| Borland C++ Builder compiler (vs typical MSVC) | LOW — unusual but not unique |

**Confidence limitations:** The specific SHA256 hashes are not in published open-source IoC tables. These samples represent a March 16 second wave; ThreatLabz reporting covers the March 1 first wave only. No direct code-similarity match (ssdeep/YARA) against confirmed Mustang Panda samples was validated.

---

## Detection Guidance

### YARA Rules

```yara
rule MustangPanda_ShellFolderDepend_Loader {
    meta:
        description = "Mustang Panda BaiduNetdisk DLL sideload loader - forged Tencent metadata"
        date        = "2026-04-05"
        tlp         = "WHITE"
        author      = "REMnux analysis"
    strings:
        $exp1 = "_RigsterHook@0" ascii
        $exp2 = "_UnRigsterHook@0" ascii
        $meta1 = "Tencentdl Module" wide
        $meta2 = "dlcore.dll" wide
        $borland = "Borland" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($exp1 and $exp2) or ($meta1 and $meta2 and $borland))
}

rule MustangPanda_CHM_BaiduNetdisk_Dropper {
    meta:
        description = "Mustang Panda CHM dropper containing BaiduNetdisk sideloading kit"
        date        = "2026-04-05"
        tlp         = "WHITE"
    strings:
        $f1 = "BaiduNetdisk/ShellFolder.exe" ascii
        $f2 = "BaiduNetdisk/ShellFolderDepend.dll" ascii
        $f3 = "Shelter.ex" ascii
        $f4 = "07TACBPR9" ascii
    condition:
        ($f1 and $f2) or ($f1 and $f3)
}

rule MustangPanda_PlugX_Shellcode_Decrypted {
    meta:
        description = "Mustang Panda PlugX shellcode after RC4 decryption (Shelter.ex)"
        date        = "2026-04-05"
        tlp         = "WHITE"
    strings:
        // GetPC + anti-disassembly pattern at shellcode start
        $getpc = { 3B EB 02 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 00 }
    condition:
        $getpc at 0
}
```

### Network Detections

- Block/alert: all DNS queries and HTTPS connections to `360printsol[.]com` and subdomains
- Alert: HTTPS connections to `91.193.17[.]117:443`
- Alert: DoH queries (port 443 to non-standard DNS resolvers) from endpoints

### Endpoint Detections

```
Alert: cmd.exe child of hh.exe (HTML Help)
Alert: ShellFolder.exe loading ShellFolderDepend.dll from %APPDATA%\BaiduNetdisk\
Alert: SystemFunction033 called from non-system module (dynamic RC4 abuse)
Alert: Registry write HKCU\...\Run\BaiNetdisk
Hunt:  filename Shelter.ex in any user-writable path
Hunt:  PE exports matching _RigsterHook@0 or _UnRigsterHook@0
Hunt:  imphash 551af7f202e2768c63b16f27eadd2d27
```

---

## Open-Source References

| Source | URL |
|--------|-----|
| Zscaler ThreatLabz (primary) | https://www.zscaler.com/blogs/security-research/china-nexus-threat-actor-targets-persian-gulf-region-plugx |
| Security Boulevard mirror | https://securityboulevard.com/2026/03/china-nexus-threat-actor-targets-persian-gulf-region-with-plugx/ |
| ThreatLabz — Mustang Panda PAKLOG/SplatCloak | https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-paklog-corklog-and-splatcloak-p2 |

---

## Analysis Toolchain

Static analysis performed on REMnux via MCP server using:
`7z`, `file`, `exiftool`, `strings`, `xxd`, `ndisasm`, `pecheck.py`, `peframe`, `manalyze`, `capa`, `floss`, `signsrch`, `xorsearch`, `ssdeep`, `pdfid.py`, `pdf-parser.py`, `diec`, `openssl`, `perl` (RC4 decryption primitive)

*Report generated: 2026-04-05 | REMnux + OSINT*
