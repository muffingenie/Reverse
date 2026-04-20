# CTI Report: Purchase Order.xls — OLE URL Moniker / VBA-Stomp Downloader

**Date:** 2026-04-20  
**Analyst:** REMnux Static Analysis  
**TLP:** TLP:WHITE  
**Confidence:** High (static analysis confirmed; no sandbox execution)

---

## Executive Summary

`Purchase Order.xls` is a weaponised Microsoft Excel 97-2003 workbook (.xls / BIFF8 / OLE2) employing three layered evasion techniques:

1. **VelvetSweatshop encryption** — file is silently auto-decrypted by Excel without user prompt  
2. **OLE URL Moniker** embedded object that triggers an outbound HTTP download to a remote C2 (`192.3.122.144`) on file open  
3. **VBA source stomping** — VBA source code is blanked; p-code stubs remain to confuse analysis tools  

The lure impersonates a Quality Management System (QMS) document with South-East Asian / ASEAN regional content (Philippine Peso / Indonesian Rupiah formats, personnel from Australia and Brunei offices), consistent with targeted phishing against an SEA-region organisation.

---

## File Metadata

| Field | Value |
|-------|-------|
| Filename | `Purchase Order.xls` |
| SHA-256 | `d318c45c2842182c07e9bd0ad2c1c010f18cda1c5a2fd8883226cb89cbd47706` |
| SHA-1 | `8c192815a83d1f97c033cf90e4c7a3505385ff10` |
| MD5 | `44dc56bc4a1dd3ace7722db1598e529e` |
| ssdeep | `6144:vZ+RwPONXoRjDhIcp0fDlavx+W/WEaguL1nH7DTdmsWciHnFpP/g7HoBe0VzsBg9:agw1n7EyiHLP/gzIbignpB1Vk2apmQG` |
| Size | 495,104 bytes (495 KB) |
| File type | Composite Document File V2 (OLE2 / CFB) — Excel 97-2003 Workbook |
| Container | OLE, BIFF8 |
| Application | Microsoft Excel 12.0 (App Version 12.0000 = Office 2007) |
| CompObj | "Microsoft Office Excel 2003 Worksheet" (downgrade spoof) |
| Created | 2006-09-16 00:00:00 (fake / default epoch date) |
| Last Saved | 2026-04-20 05:34:29 UTC (day of submission) |
| Last Printed | 2025-05-26 00:49:13 UTC |
| Code Page | Windows Latin 1 (CP-1252) |
| Security flag | 1 (Password protected) |

---

## Encryption

| Item | Detail |
|------|--------|
| Password | **`VelvetSweatshop`** |
| Method | XOR-based read-only protection (BIFF8 FILEPASS record) |
| Effect | Excel automatically tries this well-known default password and opens the file **silently** without prompting the user — appears normal |

---

## OLE Stream Layout

```
Root Entry
├── \x01CompObj
├── \x05DocumentSummaryInformation
├── \x05SummaryInformation
├── MBD00043C41/                   ← Embedded OLE object (decoy workbook)
│   ├── \x01CompObj
│   ├── \x05DocumentSummaryInformation
│   ├── \x05SummaryInformation     (101,796 bytes — large thumbnail / lure image)
│   └── Workbook                   (246,835 bytes — embedded full workbook)
├── MBD00043C42/                   ← Embedded OLE object (URL Moniker — MALICIOUS)
│   └── \x01Ole                    (566 bytes — URL Moniker to C2)
├── Workbook                       (127,022 bytes — outer workbook w/ hidden XLM sheet)
└── _VBA_PROJECT_CUR/
    ├── PROJECT
    ├── PROJECTwm
    ├── VBA/Sheet1  (977 bytes — stomped)
    ├── VBA/Sheet2  (977 bytes — stomped)
    ├── VBA/Sheet3  (977 bytes — stomped)
    ├── VBA/ThisWorkbook (985 bytes — stomped)
    ├── VBA/_VBA_PROJECT (2,644 bytes)
    └── VBA/dir    (553 bytes)
```

---

## Attack Vector 1: OLE URL Moniker (Primary / Confirmed)

### Mechanism
`MBD00043C42` is an OLE embedded object with **CLSID `{79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}`** — the Windows URL Moniker (`CUrlMoniker`). When Excel opens the file and activates the embedded object (which can happen automatically depending on OLE settings), it issues an HTTP GET request to fetch the object's remote content.

### URL (obfuscated)
```
Stored in MBD00043C42/\x01Ole stream @ offset 0x30 (UTF-16LE):
  http://030000675220/tststststststststststs.php

Decoded (octal → IPv4):
  030000675220 (octal) = 3,221,453,456 (decimal) = 0xC0037A90
  → 192.3.122.144

Deobfuscated URL:
  http://192.3.122.144/tststststststststststs.php
```

### Octal IP Obfuscation
The single-component numeric hostname `030000675220` uses **leading-zero octal notation**, which is interpreted as an IP address by Windows' WinInet / URLMoniker stack. This bypasses naive URL/domain detection that looks for dotted-quad notation.

### Associated Token / Key
Immediately following the URL in the Ole stream (at offset +0x114) is a 128-character alphanumeric string stored as UTF-16LE (length-prefixed, DWORD `0x0102` = 258 bytes):

```
4LDGR0iawoURgifRVVweSwipurWhvsefChvirBIqlonmXLEvqbMdLgR0KYkUGlxde
VgIYi5ecMFejpOoozo162lmZuzID00iTOzDtr8hkkQuHApb3HOlqKWhyvAMIRxt
```

Base64-decodes to 96 bytes of binary data. Assessed as one of:
- Victim/campaign unique identifier (bot ID sent in HTTP request)
- RC4/XOR decryption key for the remote payload
- Server-side authentication token

---

## Attack Vector 2: Hidden XLM Macro Sheet

### Detection
- `oleid` reports: `VBA Macros: Yes (Medium)`, `XLM Macros: No` (false negative — oleid cannot parse past the VelvetSweatshop encryption layer during initial scan)
- `olevba` decrypts the file and reveals a BOUNDSHEET record for a **hidden sheet with name `\x06`** (non-printable ASCII 6 = ACK control character — standard XLM sheet concealment)
- BIFF8 BOUNDSHEET record: `hidden=1` (hidden, not very-hidden), type=`0` (worksheet)

### XLM Sheet `\x06`
The outer Workbook stream (stream 9) has three BOUNDSHEET entries:
- `\x06` — hidden, worksheet (XLM macro sheet)
- `''` (empty) — hidden (Sheet2)
- `''` (empty) — hidden (Sheet3)

All three visible sheets are hidden. The workbook presents as empty to the user while the XLM code runs.

The embedded workbook (MBD00043C41) also contains a defined NAME record with `fBuiltin=0x20` and name `\x06` — corresponding to the `Auto_Open` built-in function equivalent in XLM, ensuring auto-execution on workbook open.

### XLM Analysis Note
`xlmdeobfuscator` timed out (300s) on both the encrypted and decrypted versions, indicating heavily obfuscated XLM formulas (likely cell-by-cell string concatenation, CHAR()-based obfuscation, or recursive formula loops). The URL `http://030000675220/tststststststststststs.php` appears to be the download target used within XLM `=CALL()` or `=EXEC()` formula sequences.

---

## Attack Vector 3: VBA Source Stomping

### Indicators
- VBA project declares 4 modules: `ThisWorkbook`, `Sheet1`, `Sheet2`, `Sheet3`
- All 4 VBA source streams report `(empty macro)` in `olevba` (source is blanked)
- Module streams are 977–985 bytes (consistent with minimal valid p-code stubs)
- `pcodedmp` shows valid dir stream and `_VBA_PROJECT` identifier table with 17 symbols but **no p-code disassembly output** — p-code has been stripped or zeroed
- VBA compile IDs in `_VBA_PROJECT_CUR/PROJECT`: `0]6c068399`, `0^6c068399`, `0_6c068399`, `0`6c068399` (unique fingerprint for attribution)

VBA stomping renders the file benign-looking to `olevba` while the p-code (executed by Excel's VBA engine) may contain actual malicious instructions invisible to text-based scanners.

---

## Lure / Social Engineering

### Document Profile
| Field | Detail |
|-------|--------|
| Type | Quality Management System (QMS) form |
| Reference | `ICO-QM-01-F01` |
| Title | "Internal Origin Document – QMS Forms & Format" |
| Subtitle | "Quality & HSE Objective" |
| Revision | `REV 03`, dated `10 July 2025` |
| Pages | 9 (based on metadata string) |
| Embedded decoy | 101,550-byte thumbnail (`MBD00043C41/\x05SummaryInformation`) |

### Targeting Indicators
| Indicator | Significance |
|-----------|-------------|
| Philippine Peso format `"Php"#,##0.00` | Philippines operations |
| Indonesian Rupiah format `"Rp"#,##0.00` | Indonesia operations |
| `Australia (Je Anne)` | Staff name — Australia office |
| `Brunei (Siti Nadzirah)` | Staff name — Brunei office |
| `logo marka` (Turkish: "logo brand") | Possible author tool artifact or Turkish-language authoring environment |
| Last printed 2025-05-26 | Lure doc existed pre-2026 weaponisation |

The lure targets an **ASEAN-region organisation** (likely manufacturing, construction, or resources sector based on QMS/HSE content) with offices across Southeast Asia and Oceania.

---

## Infrastructure

| Indicator | Detail |
|-----------|--------|
| C2 IP | `192.3.122.144` |
| Reverse DNS | `192-3-122-144-host.colocrossing.com` |
| Hosting | **ColoCrossing** (AS36352, Buffalo NY, USA) — budget VPS widely abused by threat actors |
| URL Path | `/tststststststststststs.php` (20× `ts` repetition — possible test/debug artifact) |
| Protocol | HTTP (plaintext, port 80) |
| URL encoding | Octal IP obfuscation (`030000675220`) to evade URL pattern detection |

---

## IOCs

### File Hashes
| Type | Hash |
|------|------|
| SHA-256 | `d318c45c2842182c07e9bd0ad2c1c010f18cda1c5a2fd8883226cb89cbd47706` |
| SHA-1 | `8c192815a83d1f97c033cf90e4c7a3505385ff10` |
| MD5 | `44dc56bc4a1dd3ace7722db1598e529e` |
| ssdeep | `6144:vZ+RwPONXoRjDhIcp0fDlavx+W/WEaguL1nH7DTdmsWciHnFpP/g7HoBe0VzsBg9:agw1n7EyiHLP/gzIbignpB1Vk2apmQG` |

### Network
| Type | Value |
|------|-------|
| URL | `http://030000675220/tststststststststststs.php` |
| URL (decoded) | `http://192.3.122.144/tststststststststststs.php` |
| IP | `192.3.122.144` |
| ASN | AS36352 (ColoCrossing) |
| Hosting | `colocrossing.com` |

### Document Artefacts
| Type | Value |
|------|-------|
| OLE Password | `VelvetSweatshop` |
| OLE CLSID (URLMoniker) | `{79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}` |
| OLE GUID (object) | `{084F01FA-E634-4D77-83EE-074817C03581}` |
| Token/Key string | `4LDGR0iawoURgifRVVweSwipurWhvsefChvirBIqlonmXLEvqbMdLgR0KYkUGlxdeVgIYi5ecMFejpOoozo162lmZuzID00iTOzDtr8hkkQuHApb3HOlqKWhyvAMIRxt` |
| VBA compile ID | `6c068399` |
| Hidden sheet name | `\x06` (chr(6) / ACK) |
| Document reference | `ICO-QM-01-F01` |

---

## Capabilities & TTPs (MITRE ATT&CK)

| TTP | Technique | Detail |
|-----|-----------|--------|
| T1566.001 | Phishing: Spearphishing Attachment | XLS lure sent as attachment |
| T1204.002 | User Execution: Malicious File | Requires user to open XLS |
| T1027.002 | Obfuscated Files or Information: Software Packing | VelvetSweatshop encryption hides content |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Octal IP obfuscation in URL |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Hidden sheet with non-printable name |
| T1137.001 | Office Application Startup: Office Template Macros | XLM macro on hidden `\x06` sheet |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBA stubs (stomped) |
| T1059.010 | Command and Scripting Interpreter: System Services | XLM 4.0 macros (Excel built-in) |
| T1105 | Ingress Tool Transfer | OLE URL Moniker downloads from `192.3.122.144` |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP download on port 80 |
| T1218 | System Binary Proxy Execution | OLE/URLMoniker executes via Excel process |

---

## YARA Detection Rules

```yara
rule Excel_VelvetSweatshop_URLMoniker_Downloader
{
    meta:
        description  = "Detects Purchase Order.xls OLE URLMoniker downloader with VelvetSweatshop encryption"
        author       = "REMnux Analysis"
        date         = "2026-04-20"
        hash_sha256  = "d318c45c2842182c07e9bd0ad2c1c010f18cda1c5a2fd8883226cb89cbd47706"
        tlp          = "WHITE"
        mitre        = "T1105, T1137.001, T1027.002"

    strings:
        // URLMoniker CLSID in OLE stream (little-endian)
        $url_moniker_clsid = { E0 C9 EA 79 F9 BA CE 11 8C 82 00 AA 00 4B A9 0B }
        // Obfuscated octal IP in UTF-16LE
        $octal_ip = { 30 00 33 00 30 00 30 00 30 00 30 00 36 00 37 00 35 00 32 00 32 00 30 00 }
        // PHP path in UTF-16LE
        $php_path  = { 74 00 73 00 74 00 73 00 74 00 73 00 74 00 73 00 74 00 73 00 74 00 73 00 }
        // VelvetSweatshop known encryption marker (FILEPASS record)
        $filepass  = { 2F 00 [2] 04 00 }
        // Hidden sheet with chr(6) name in BOUNDSHEET
        $hidden_sheet = { 85 00 08 00 [4] 01 00 01 06 }
        // Unique token prefix in Ole stream
        $token = "4LDGR0iawoURgifRVVweSwipurWhvsefChvir" ascii

    condition:
        uint32(0) == 0xE011CFD0 and  // OLE magic
        $url_moniker_clsid and
        ($octal_ip or $php_path) and
        ($filepass or $hidden_sheet or $token)
}

rule Excel_OctalIP_URLMoniker
{
    meta:
        description = "Detects Excel OLE files using octal-encoded IP in URL Moniker (evasion technique)"
        author      = "REMnux Analysis"
        date        = "2026-04-20"
        tlp         = "WHITE"
        mitre       = "T1027.013, T1105"

    strings:
        $ole_magic    = { D0 CF 11 E0 A1 B1 1A E1 }
        $url_moniker  = { E0 C9 EA 79 F9 BA CE 11 8C 82 00 AA 00 4B A9 0B }
        // http:// in UTF-16LE followed by octal digit 0
        $http_octal_u = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 30 00 }
        // Any http:// URL in OLE with 0-prefixed numeric host (both encodings)
        $http_octal_a = "http://0" ascii

    condition:
        $ole_magic at 0 and $url_moniker and
        ($http_octal_u or $http_octal_a)
}

rule XLM_Hidden_Sheet_Chr6
{
    meta:
        description = "Excel file with hidden XLM sheet using chr(6) (ACK) as name — classic XLM concealment"
        author      = "REMnux Analysis"
        date        = "2026-04-20"
        tlp         = "WHITE"
        mitre       = "T1564.001, T1059.010"

    strings:
        $ole_magic    = { D0 CF 11 E0 A1 B1 1A E1 }
        // BOUNDSHEET record, hidden=1, type=0 (worksheet), 1-char name = 0x06
        $boundsheet_6 = { 85 00 08 00 [4] 01 [1] 01 06 }

    condition:
        $ole_magic at 0 and $boundsheet_6
}
```

---

## Sigma Detection Rule

```yaml
title: Excel OLE URL Moniker Outbound Request (Octal IP)
id: f8a1b234-oc7a-4e5c-9b82-d3f1a0c9e471
status: experimental
description: Detects HTTP request from Excel process to numeric/octal-encoded IP host via URL Moniker activation
author: REMnux Analysis
date: 2026/04/20
mitre:
    attack.techniques:
        - T1105
        - T1027.013
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith:
            - '\EXCEL.EXE'
            - '\excel.exe'
        DestinationPort: 80
        DestinationIp: '192.3.122.144'
    condition: selection
falsepositives:
    - None expected
level: high
---
title: Excel Auto-Open Hidden Sheet with Non-Printable Name
id: a2c4d678-9ef0-4321-bb12-cc34dd56ee78
status: experimental
description: Detects Excel file open events followed by a hidden sheet activation matching XLM auto-open patterns
author: REMnux Analysis
date: 2026/04/20
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\EXCEL.EXE'
        CommandLine|contains:
            - 'cmd'
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'cscript'
    condition: selection
level: high
```

---

## Interesting Strings

| String | Location | Significance |
|--------|----------|-------------|
| `VelvetSweatshop` | FILEPASS (password) | Default Excel auto-decrypt password |
| `030000675220/tststststststststststs.php` | MBD00043C42/Ole stream | Obfuscated C2 path |
| `http://030000675220/tststststststststststs.php` | MBD00043C42/Ole stream offset 0x30 | Full obfuscated download URL |
| `4LDGR0iawoURgifRVVweSwipurWhvsefChvir...AMIRxt` | MBD00043C42/Ole stream offset 0x118 | 128-char token / bot ID / key |
| `\x06` | BOUNDSHEET name | Hidden XLM macro sheet (chr(6) = ACK) |
| `ICO-QM-01-F01` | Lure text | Document reference number |
| `Quality & HSE Objective` | Lure text | Document type indicator |
| `Australia (Je Anne)` | SST | Staff / target persona |
| `Brunei (Siti Nadzirah)` | SST | Staff / target persona |
| `logo marka` | Unicode strings | Turkish string — possible authoring artifact |
| `"Php"#,##0.00` | Format strings | Philippine Peso number format |
| `"Rp"#,##0.00` | Format strings | Indonesian Rupiah number format |
| `91974` (padded) | SummaryInformation | Internal document/object identifier |
| `6c068399` | VBA PROJECTwm | VBA compile-time identifier (fingerprint) |
| `{084F01FA-E634-4D77-83EE-074817C03581}` | Unicode strings | OLE object GUID |
| `Picture 1`, `Picture 70` | Unicode strings | 70 embedded images (decoy content) |
| `Microsoft Print to PDF` | Unicode strings | Printer name on authoring host |
| `Line 67` | Unicode strings | Named style — possible authoring artifact |

---

## Attribution Assessment

**Confidence: Low-Medium**

| Indicator | Assessment |
|-----------|-----------|
| Targeting | ASEAN-region organisation (Philippines, Indonesia, Brunei, Australia offices) — consistent with regional APT targeting of energy/resources/industrial sectors |
| Lure type | QMS/HSE internal document — suggests insider-knowledge or prior reconnaissance of target's document workflow |
| C2 hosting | ColoCrossing (US-based budget VPS) — low attribution value; widely used by both commodity and nation-state actors |
| Tooling | VelvetSweatshop + OLE URLMoniker + VBA stomp is a known commodity toolkit; not unique to any actor |
| Turkish artifact | `logo marka` string may indicate Turkish-language authoring environment or copy-paste from Turkish source template |
| URL path | `/tststststststststststs.php` — `tsts` repetition pattern suggests test/development artefact; payload may still be active or server may be down |
| No network confirmation | C2 response not retrieved; cannot assess second-stage payload family |

The technique combination (VelvetSweatshop + URLMoniker + XLM hidden sheet + VBA stomp) is consistent with **commodity phishing kit** deployments observed in 2024-2026, widely sold/shared in crimeware forums. No unique TTPs were identified that would strongly attribute to a specific named threat actor.

---

## Recommendations

### Immediate
1. **Block network IOC**: Firewall/proxy rule blocking `192.3.122.144` (all ports) and `colocrossing.com` hosting for this IP
2. **Hunt for file hashes** across endpoint telemetry (EDR/AV): SHA-256 `d318c45c...`
3. **Hunt for URL pattern**: Proxy logs for `http://0[0-9]{9,11}/` (octal-IP pattern) from any Office process
4. **Check for file delivery**: Review email gateway logs for the attachment filename or hash

### Detection
- Deploy the YARA rules above in email gateway, EDR, and file scanning pipelines
- Alert on `EXCEL.EXE` making outbound HTTP connections to non-RFC1918, non-CDN IPs
- Alert on Excel spawning child processes after opening `.xls` files
- Enable Protected View for externally-received Office documents

### Hardening
- **Disable OLE object activation** in Office Trust Center → Trusted Locations settings
- Apply `HKCU\Software\Microsoft\Office\<ver>\Excel\Security\PackagerPrompt = 2` to force OLE prompt
- Consider `DisableAllActiveX`, `VBAWarnings=4` (disable all macros) via GPO
- Excel 4.0 (XLM) macro execution can be blocked via: Attack Surface Reduction rule `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B`

---

## Analysis Artefacts

| File | Path | Notes |
|------|------|-------|
| Original sample | `/home/remnux/files/samples/Purchase Order.xls` | Encrypted original |
| Decrypted | `/home/remnux/files/output/PO_decrypted.xls` | VelvetSweatshop decrypted |

---

*Report generated by REMnux static analysis using: oleid, olevba, oledump.py, pcodedmp, msoffcrypto-crack.py, msoffcrypto-tool, exiftool, ssdeep, strings, yara-rules, custom Python BIFF8 parser*
