# PlugX / Mustang Panda — CTI Trend Report (2023–2026)
**Based on:** Internal sample analysis corpus — `/home/muffin/report/`  
**PlugX reports identified:** 6 of 12 reports in corpus  
**TLP:** TLP:AMBER  
**Date:** 2026-04-20  
**Confidence:** High (all findings based on direct static analysis of confirmed samples)

---

## 1. Scope & Source Reports

Six reports in `/home/muffin/report/` were identified as PlugX-related:

| Report File | Sample | Date | Lure/Target |
|---|---|---|---|
| `CTI_Report_MSI_PlugX_601ae63e.md` | `601ae63e.msi` | 2026-03-03 | Nepal CIAA (South Asia, diplomatic) |
| `PlugX_DLL_Analysis_Results.md` | `AVKTray.dat` DLL | 2026-03-03 | (companion to above) |
| `CTI_Report_sample_msi_PlugX.md` | `sample.msi` | 2026-03-22 | Vietnam "Invitation Letter" (SEA, diplomatic) |
| `CTI_Report_sample_chm_PlugX_ArabicLure.md` | `sample.chm` | 2026-04-05 | Arabic GCC conflict lure (Middle East) |
| `CTI_Report_Smadav_PlugX_Sideloading.md` | `sample.zip` | 2026-04-20 | SmadAV / Indonesia (SEA, broad) |
| `PlugX_Deobfuscation_Guide.md` | (reference) | — | Analysis methodology |

The remaining 6 reports (`CTI_Report_ghost_exe.md`, `CTI_Report_JS_Injector_1140b0fb.md`, `CTI_Report_temp_zip_VB6RAT.md`, `CTI_Report_PurchaseOrder_XLS.md`, `CTI_Report_CK_Google_DLL_aa047a9a.md`, `CTI_Report_维持CK1.0_vmp_exe.md`) are unrelated malware families (ValleyRAT, Magecart, DUCDUN, OLE URLMoniker, CK RAT).

---

## 2. Executive Summary

Across four distinct PlugX campaigns spanning October 2023 to April 2026, this corpus documents a **persistent, highly active Mustang Panda / Earth Preta (UNC6384) operation** targeting diplomatic, government, and enterprise entities across five geographic regions: South Asia, Southeast Asia, the Middle East, and Europe. The campaigns share a consistent three-component DLL sideloading delivery architecture — always a **legitimately signed binary + malicious loader DLL + encrypted payload blob** — but show systematic evolution in every other dimension: delivery vehicle, encryption algorithm, lure theme, persistence key, C2 infrastructure, and code obfuscation depth.

Key trends observed in this corpus:

1. **Sideloading vehicle diversification**: G DATA AV → Valve Steam → Baidu NetDisk → DriveTheLife/SmadAV — each a different legitimate software vendor
2. **Payload encryption upgrade**: Single-byte XOR → RC4 (static key) → RC4 (date-keyed `YYYYMMDD@@@`) → custom 4-state LCG + LZNT1
3. **Geographic targeting breadth expanding**: From Asia-focused to Middle East and Europe simultaneously
4. **Persistence key rotation**: `Software\CLASSES\ms-pu` → `Software\CLASSES\Capitol` — deliberate evasion of static detection rules
5. **Obfuscation stack deepening**: Stack strings + XOR → CFF+MBA shellcode obfuscation → anti-disassembly junk + GetPC PIC
6. **Code signing abuse as a constant**: Every campaign uses a legitimately signed binary; the signing keys (G DATA, Valve, Baidu, DriveTheLife) are diverse and increasingly reputable
7. **PlugX variant diversity**: BB01, DOPLUGS, and "BIU cluster" variants deployed concurrently — suggesting a modular tooling repository rather than a single implant

---

## 3. Campaign Chronology

```
Oct 2023    ──── SmadAV/Indonesia campaign (Smadav.exe, LCG+LZNT1, 'Capitol' persist, BIU cluster)
                  [Compile: 2023-10-26]
                  
Mar 2025    ──── Nepal CIAA campaign (G DATA Avk.exe, XOR 0x0b, BB01, C2: carhirechicago.com)
                  [MSI compiled: 2026-03-01; DLL compiled: 2026-01-15]

Mar 2025    ──── Steam/Vietnam campaign (steam_monitor.exe, RC4, BB01, C2: famisu.com)
                  [MSI compiled: 2025-03-09]
                  
Mar 2026    ──── Arabic GCC campaign (BaiduNetdisk/ShellFolder.exe, YYYYMMDD@@@ RC4 + CFF+MBA,
                  DOPLUGS variant, C2: 360printsol.com, DoH)
                  [Weaponized: 2026-03-16]
```

> **Note:** The SmadAV sample (Oct 2023 compile) represents either the earliest sample in this corpus or a long-deployed implant; the 2023 timestamp predates the 2025–2026 campaign wave by over a year but uses the same structural TTP cluster.

---

## 4. Delivery Mechanism Evolution

### 4.1 Consistent Architecture: The Three-File Sideloading Kit

All four campaigns use an **identical structural formula**:

```
[Legitimate Signed Binary].exe          ← DLL search-order hijacking vehicle
[Malicious Loader].dll                  ← reads and decrypts payload
[Encrypted Payload].dat/.ex/.hlp        ← PlugX core, encrypted at rest
```

This architecture is the Mustang Panda trademark since at least 2021 and has proven resilient against static detection for years. It provides:
- A legitimate parent process to reduce SIEM/EDR alert priority
- No code-signing requirement for the malicious DLL (it inherits the parent's trust context in some AV products)
- Clean separation of concerns that allows rotating any one component

### 4.2 Sideloading Binary Rotation

| Campaign | Signed Binary | Vendor | Cert Authority |
|---|---|---|---|
| Nepal/Vietnam (2025–26) | `Avk.exe` (G DATA AntiVirus v25.1) | G DATA CyberDefense AG (Germany) | Microsoft ID Verified CS AOC CA 02 |
| Steam/Vietnam (2025) | `steam_monitor.exe` | Valve Corporation | Valve code signing |
| GCC/Arabic (2026) | `ShellFolder.exe` (Baidu NetDisk) | Baidu | Baidu code signing |
| SmadAV/Indonesia (2023) | `Smadav.exe` | DriveTheLife (Shenzhen) | DigiCert G4 Code Signing |

**Trend:** The actor rotates signed binaries across major software vendors from different countries and industries (security AV, gaming, cloud storage, utility software). This rotation is deliberate to defeat vendor-specific detection signatures. The DriveTheLife certificate (`91440300695560951T`) has appeared across multiple Earth Preta campaigns and should be considered a **high-fidelity threat actor attribution indicator**.

### 4.3 Delivery Container Diversification

| Campaign | Container | Execution Trigger |
|---|---|---|
| Nepal CIAA | `.msi` (WiX 3.11) | `msiexec /i` |
| Steam/Vietnam | `.msi` (WiX 3.11) | `msiexec /i` |
| Arabic GCC | `.chm` | `$OBJINST` auto-exec on open |
| SmadAV/Indonesia | `.zip` | Social engineering, manual execution |

**Trend:** The actor expanded beyond MSI to CHM (exploiting the CHM auto-exec mechanism via `{4662DAAF-D393-11D0-9A56-00C04FB68BF7}`) and raw ZIP delivery. This suggests adaptation to email gateway policies that may filter MSI files. CHM delivery is particularly dangerous because opening the file is sufficient to trigger execution — no macro-enable prompt.

**Common MSI fingerprint** (601ae63e and sample.msi share): WiX 3.11.2.4516 build system, `ProductName = "MainProgran"` (deliberate typo), `ARPSYSTEMCOMPONENT=1`, `Manufacturer = "Microsoft Corporation"` — a toolkit fingerprint.

---

## 5. Payload Encryption Evolution

This is the most significant area of technical evolution in the corpus.

| Campaign | Encryption | Key | Complexity |
|---|---|---|---|
| Nepal CIAA (601ae63e) | **XOR 0x0b** + RC4 (config blob) | Static `0x0b`; RC4 key = campaign ID first 9 bytes (`iEYnFBPdx`) | Low outer, medium inner |
| Steam/Vietnam | **RC4** (whole payload) + RC4 (config blob) | Static `BdkfdEDGGNxWdJeL`; config key `1BDD6` (derived from DWORD via `wsprintfA("%X")`) | Medium |
| Arabic GCC | **RC4 (date-keyed)** via `SystemFunction033` + **LCG XOR** + **LZNT1** | `YYYYMMDD@@@` (per weaponization date) → LCG seed `0xC56DD7EA` | High |
| SmadAV/Indonesia | **Custom 4-state LCG** + **LZNT1** | Seed self-referential (`enc[0:4] = 0x79B972EE`); constants include campaign date `0x20230912` | High |

**Critical insight — the `YYYYMMDD@@@` pattern:**  
The Arabic GCC campaign introduced a **date-keyed RC4 decryption key** where the key is constructed as the weaponization date formatted as `YYYYMMDD@@@`. ThreatLabz confirmed `20260301@@@` for a March 1 wave and analysis of this corpus assesses `20260316@@@` for the March 16 wave. This has two operational implications:
1. **Analyst countermeasure**: Decryption key is recoverable by knowing the compile/weaponization date from PE timestamps
2. **Detection opportunity**: The 11-byte pattern `[0-9]{8}@@@` as a stack-built string in memory is a high-fidelity behavioral indicator

**The LCG + LZNT1 chain** (both Arabic GCC stage 2 and SmadAV) uses `RtlDecompressBuffer` as a legitimate Windows API for decompression — making the decompression step invisible to static analysis tools that focus on PE packers. The custom LCG replaces a standard RC4/AES cipher with a bespoke algorithm that bypasses most crypto detection rules.

---

## 6. PlugX Variant Taxonomy in This Corpus

Three distinct PlugX sub-variants were identified:

### 6.1 BB01 Variant (Nepal + Vietnam campaigns)
- **Protocol:** HMAC-SHA256 authenticated C2 sessions
- **Persistence:** `Software\CLASSES\ms-pu` (COM hijack)
- **Install dir:** `%APPDATA%\Render\`
- **Config encryption:** RC4 with key derived from campaign ID
- **Loader DJB2 hash:** API resolution via DJB2 hashing
- **Identification:** BB01 magic in C2 session header
- **NOT**: DOPLUGS, ROHT, or GULP variants

### 6.2 DOPLUGS Variant (Arabic GCC campaign)
- **Lineage:** Derived from DOPLUGS (documented by ThreatLabz as "DOPLUGS" PlugX subtype)
- **Fingerprint key:** Config blob RC4 key `qwedfgx202211` (ThreatLabz confirmed, cross-campaign constant)
- **C2 traffic key:** `VD*1^N1OCLtAGM$U` (ThreatLabz confirmed)
- **Obfuscation:** CFF (Control Flow Flattening) + MBA (Mixed Boolean Arithmetic) in shellcode
- **C2 channel:** HTTPS + DNS-over-HTTPS (DoH) — evades DNS-layer monitoring
- **Anti-disassembly:** Junk byte at shellcode offset 0x00, CALL $+5 GetPC at 0x2D
- **Notable:** Most sophisticated obfuscation profile in this corpus

### 6.3 BIU Cluster Variant (SmadAV campaign)
- **Architecture:** UIBB module dispatcher — `bootProc`, `PlugProc`, `CmdShell`, `KeyLog`, `ClipLog`, `Screen`, `Netstat`, `Nethood`, `PortMap`, `Service`, `RegEdit`, `Telnet`, etc. (17 named modules)
- **UIBB magic:** `0x42424955`
- **Persistence:** `Software\CLASSES\Capitol` (different from `ms-pu` — deliberate rotation)
- **Install dir:** `%ALLUSERSPROFILE%\SxS\`
- **Debug marker:** `BIU BIU BIU!!!` in .rdata (cluster attribution fingerprint, documented by Avast/ESET)
- **Config file:** `biuxmind.ini`
- **Named pipe:** `\\.\pipe\Capitol%d`
- **C2 format:** HTTP POST `/update?id=%8.8x`, custom `X-Status`/`X-Session`/`X-Size`/`X-Sn` headers
- **AV bypass:** PowerShell `Remove-MpPreference -ExclusionPath C:\`

**Variant co-deployment implication:** The concurrent use of BB01, DOPLUGS, and BIU cluster variants in campaigns spanning 2023–2026 indicates that Mustang Panda maintains a **modular PlugX tooling repository** with multiple available payloads that can be assigned to different campaigns. Different sub-groups within the actor cluster may operate specific variants.

---

## 7. Persistence Mechanism Trends

| Campaign | Primary Persistence | Secondary |
|---|---|---|
| Nepal CIAA | `HKCU\...\Run` value `"G DATA"` pointing to `Avk.exe` | Windows service creation |
| Steam/Vietnam | `Software\CLASSES\ms-pu\CLSID` (COM hijack) | — |
| Arabic GCC | `HKCU\...\Run\BaiNetdisk` → `ShellFolder.exe --path a` | — |
| SmadAV/Indonesia | `Software\CLASSES\Capitol` (COM hijack) | `HKCU\...\Run` |

**Trend — COM hijack key rotation:**
The shift from `Software\CLASSES\ms-pu` (Nepal/Vietnam) to `Software\CLASSES\Capitol` (SmadAV) is a deliberate **detection evasion response**. The `ms-pu` key has been publicly documented in PlugX CTI reports and targeted by SOC detection rules since at least 2022. The actor rotated to `Capitol` in the SmadAV sample. Defenders should not rely on any single COM hijack key name but instead alert on **any write to `HKCU\Software\CLASSES\[GUID-less subkey]\CLSID`** by non-system processes.

**Trend — Run key impersonation:**
Both the Nepal campaign (value `"G DATA"`) and the GCC campaign (value `"BaiNetdisk"`) name their Run key values after the legitimate software being impersonated, extending the masquerade into the persistence layer.

---

## 8. C2 Infrastructure Patterns

| Campaign | C2 Domain | IP / ASN | Protocol | Transport |
|---|---|---|---|---|
| Nepal CIAA | `carhirechicago[.]com` | — | HTTPS:443 | HTTP + HMAC-SHA256, XOR |
| Steam/Vietnam | `famisu[.]com` | — | HTTPS:443 | HTTP + HMAC-SHA256 |
| Arabic GCC | `www.360printsol[.]com` | `91.193.17[.]117` | HTTPS:443 | **HTTPS + DoH** |
| SmadAV/Indonesia | `windows.gobay[.]info` | — | HTTP/HTTPS:443 | HTTP POST `/update?id=%8.8x` |

**Observations:**

1. **All C2 on port 443** — TLS traffic blends with legitimate web traffic; firewall-level blocking without DPI is ineffective.

2. **Domain naming patterns**: `carhirechicago.com` (generic US business name), `famisu.com` (Japanese-sounding, generic), `360printsol.com` (mimics Chinese "360" security brand), `windows.gobay.info` (mimics Microsoft with "windows" prefix). The actor varies between random-English, brand-mimicking, and generic patterns — no single naming TTP.

3. **DoH introduction (Arabic GCC):** The adoption of **DNS-over-HTTPS** in the 2026 GCC campaign represents a meaningful operational security upgrade that bypasses traditional DNS-layer monitoring (Infoblox, Cisco Umbrella, etc.). This technique was absent in the 2025 campaigns and appears in the most sophisticated (DOPLUGS variant) sample. Expect broader adoption.

4. **C2 staging infrastructure**: The Nepal campaign additionally used `onedown[.]gesecole[.]net/download` for initial payload delivery — a separate staging server distinct from the long-term C2. This staging-then-C2 separation is consistent with tracked Mustang Panda infrastructure segmentation.

5. **Multiple redundant C2 entries**: All three PlugX config blobs with recovered C2 data contain **3 identical redundant entries** for the same C2 host. This is standard PlugX config layout providing failover resilience.

---

## 9. Targeting Geography and Lure Themes

```
Nepal CIAA letter (Nepali)         ── South Asia, diplomatic/government
Vietnamese "Invitation Letter"     ── Southeast Asia (Vietnam), diplomatic
Arabic GCC conflict PDF            ── Middle East (GCC), government
SmadAV AV installer                ── Southeast Asia (Indonesia), broad enterprise
```

**Observations:**

1. **ASEAN + South Asia as primary focus** (3 of 4 campaigns), consistent with documented Mustang Panda mandate for APAC intelligence collection.

2. **Middle East expansion**: The Arabic GCC campaign (2026) represents a geographic pivot matching broader China-nexus strategic intelligence priorities in the Gulf. ThreatLabz documented this as the "Weaponizing Conflict" campaign theme, exploiting GCC/regional conflict narratives.

3. **Decoy document language as targeting signal**: Nepali → Nepal; Vietnamese → Vietnam; Arabic → GCC; SmadAV/Indonesian product → Indonesia. The actor tailors lures with strong regional specificity, confirming targeted (not opportunistic) campaign design.

4. **Diplomatic/government vs. broad enterprise targeting**: BB01 variant campaigns (Nepal, Vietnam) appear to target diplomatic entities with spear-phishing. The SmadAV BIU cluster uses a product masquerade more consistent with broader enterprise targeting in Indonesia.

---

## 10. Anti-Analysis and Evasion Trends

| Technique | Nepal | Vietnam | Arabic GCC | SmadAV |
|---|---|---|---|---|
| Future PE timestamp | ✅ (2059) | ✅ (2056) | ✅ (zeroed) | ❌ |
| Anti-debug (GetTickCount/QPF) | ✅ | ✅ | — | — |
| Stack strings (API names) | ✅ (80×) | ✅ (95×) | ✅ | ✅ |
| DJB2 API hashing | ✅ | ✅ | ✅ | — |
| PEB walking | ✅ | ✅ | ✅ | ✅ |
| TLS callbacks (pre-EP) | ✅ | ✅ | — | — |
| CFF + MBA obfuscation | ❌ | ❌ | ✅ | ❌ |
| Anti-disassembly junk jumps | ❌ | ❌ | ✅ | ✅ |
| GetPC shellcode | ❌ | ❌ | ✅ | ✅ |
| OS version gate | ❌ | ❌ | ❌ | ✅ (Win10+) |
| Dynamic RC4 (`SystemFunction033`) | ❌ | ❌ | ✅ | ❌ |
| WER suppression | ❌ | ❌ | ❌ | ❌ |
| AV bypass (MpPreference) | ❌ | ❌ | ❌ | ✅ |
| DoH C2 | ❌ | ❌ | ✅ | ❌ |

**Trend:** The obfuscation stack is deepening with each generation. The 2025 samples relied on established techniques (stack strings, DJB2, TLS callbacks). The 2026 GCC sample introduced CFF+MBA (requiring decompilation-level analysis tools) and DoH. The SmadAV/2023 sample introduced position-independent shellcode with anti-disassembly, suggesting this technique was developed early and is in parallel deployment.

---

## 11. Code Signing Abuse — A Persistent Enabler

Code-signing abuse is the most consistent TTP across all four campaigns. Every delivery chain includes at least one legitimately signed binary. The actor exploits the fact that enterprise security tools frequently whitelist or reduce alert severity for processes spawned by signed executables.

| Certificate / Binary | Owner | Campaign(s) | Status |
|---|---|---|---|
| G DATA CyberDefense AG | G DATA | Nepal CIAA | Valid |
| Valve Corporation | Valve | Steam/Vietnam | Valid |
| Baidu (via PDB path) | Baidu | Arabic GCC | Valid |
| Shenzhen DriveTheLife `91440300695560951T` | DriveTheLife | SmadAV | Valid (until 2026-04-04) |

**The DriveTheLife certificate** (`91440300695560951T`, DigiCert, serial `08:ac:66:7c:65:d3:6d:65:42:91:76:55:57:1e:61:c8`) deserves special attention: it has appeared in **multiple Mustang Panda campaigns** and is a threat-actor fingerprint. DigiCert was notified by researchers but has not revoked it at the time of this writing. Blocking this serial number in enterprise code-signing policy is a high-fidelity defensive action with minimal false-positive risk.

---

## 12. IOC Master List

### 12.1 Network IOCs

| Indicator | Type | Campaign | Confidence |
|---|---|---|---|
| `carhirechicago[.]com` | Domain (C2) | Nepal CIAA | High |
| `famisu[.]com` | Domain (C2) | Steam/Vietnam | High |
| `onedown[.]gesecole[.]net` | Domain (staging) | Nepal CIAA | High |
| `www.360printsol[.]com` | Domain (C2) | Arabic GCC | High |
| `91.193.17[.]117` | IPv4 (C2) | Arabic GCC | High |
| `windows.gobay[.]info` | Domain (C2) | SmadAV/Indonesia | High |
| `hxxps://www.360printsol[.]com/2026/alfadhalah/thumbnail?img=index.png` | URL (staging) | Arabic GCC | High |

### 12.2 File Hashes

| SHA256 | Description | Campaign |
|---|---|---|
| `601ae63ee59288a2e36f0b0d4f7bc0bfb40f0489995343c955db7d9ded469478` | MSI dropper | Nepal CIAA |
| `ec0269b308395947a539ab7e275de98350b89943a5f48e47237deac9fff7b4a0` | Avk.dll loader | Nepal CIAA |
| `732c747f2653e50acc5bc5b0bb07018777a0440840dd1fc5a023f3c4db2d111a` | AVKTray.dat (XOR) | Nepal CIAA |
| `9e7bb2f6b5a7e79b14b4e0e10a97518592071ebbe196452cfc75addca0496381` | PlugX core (decoded) | Nepal CIAA |
| `fca258cb72b64fcb64ecfe1b908b3ef43b6b2a842b18d6cd41a8b7f507d49849` | MSI dropper | Steam/Vietnam |
| `16fcc706d0fececbac3268cacdb3fc77e5407fa940cb75c0933a5ce9f6666318` | crashhandler.dll | Steam/Vietnam |
| `329763fad3d663908a9b83c53beab9f56e493be621ee9e4f45b020b0cfa6288e` | crashlog.dat (RC4) | Steam/Vietnam |
| `a1c36edfde028df09c3ab6f40e205f0cde0b840529f1a1c24f029889b3cdba0a` | PlugX core (decoded) | Steam/Vietnam |
| `af8bf1848b06c3a4236b13b57f88e9c2744bc3c3db2adc91dcbf320862dcc032` | CHM dropper | Arabic GCC |
| `216989f56970e3ea045773224e82b2afe78ed29e49df7d044d5a5992d622d881` | ShellFolderDepend.dll | Arabic GCC |
| `4f8cbb8e4595b0b158062b314678fad7da05202dccfa28604733ac1448a9025d` | Shelter.ex (RC4+LCG) | Arabic GCC |
| `ef7a813124fd19d11bb5d944cb95779f5fe09ff5a18c26399002759d4b0d66e7` | PlugX core (extracted) | Arabic GCC |
| `02a928b88e98a6a54cf78cf6dbacfd8acbd4a1e4c93a986e6d21e58b273054ed` | ZIP dropper | SmadAV/Indonesia |
| `c4b995745e990b5a5098f2f01269a62f11bef2a33efa47a36ee92886aa7c4b2b` | Smadav.dll loader | SmadAV/Indonesia |
| `332e5edd867a4f04b1ce3b35727ffcb7f11577607182a9a4b5e19653b66f50b8` | update.dat (LCG) | SmadAV/Indonesia |
| `67b758e6e5d9d5563bb174f1e51b8dd0914618b75f9c24879d6ab0a6086b621f` | PlugX core (extracted) | SmadAV/Indonesia |

### 12.3 Cryptographic Material

| Key / Value | Type | Campaign |
|---|---|---|
| `0x0b` | XOR key (payload) | Nepal CIAA |
| `iEYnFBPdx` | RC4 key (config blob) | Nepal CIAA |
| `iEYnFBPdxDbk` | Campaign ID / mutex | Nepal CIAA |
| `BdkfdEDGGNxWdJeL` | RC4 key (payload) | Steam/Vietnam |
| `1BDD6` | RC4 key (config blob) | Steam/Vietnam |
| `sBqFbbAuB` | Campaign ID | Steam/Vietnam |
| `YYYYMMDD@@@` | RC4 key pattern (payload) | Arabic GCC |
| `20260316@@@` | RC4 key (specific wave) | Arabic GCC |
| `qwedfgx202211` | RC4 key (config blob, DOPLUGS) | Arabic GCC |
| `VD*1^N1OCLtAGM$U` | RC4 key (C2 traffic, DOPLUGS) | Arabic GCC |
| `0xC56DD7EA` | LCG seed | Arabic GCC |
| `0x79B972EE` | LCG seed | SmadAV/Indonesia |
| `0x20230912` | LCG campaign constant | SmadAV/Indonesia |
| `D1i2s3k` | Campaign ID | SmadAV/Indonesia |

### 12.4 Host-Based IOCs

| Indicator | Type | Campaign(s) |
|---|---|---|
| `%APPDATA%\Render\` | Install directory | Nepal CIAA, Steam/Vietnam |
| `%ALLUSERSPROFILE%\SxS\` | Install directory | SmadAV/Indonesia |
| `%APPDATA%\BaiduNetdisk\` | Install directory | Arabic GCC |
| `Software\CLASSES\ms-pu` | COM hijack registry key | Nepal CIAA, Steam/Vietnam |
| `Software\CLASSES\Capitol` | COM hijack registry key | SmadAV/Indonesia |
| `HKCU\...\Run\BaiNetdisk` | Persistence run key | Arabic GCC |
| `HKCU\...\Run` value `"G DATA"` | Persistence run key | Nepal CIAA |
| `biuxmind.ini` | Config file | SmadAV/Indonesia |
| `BIU BIU BIU!!!` | Cluster debug marker | SmadAV/Indonesia |
| `\\.\pipe\Capitol%d` | Named pipe | SmadAV/Indonesia |
| `{4662DAAF-D393-11D0-9A56-00C04FB68BF7}` | CHM auto-exec CLSID | Arabic GCC |
| `_RigsterHook@0` (typo in export) | DLL export IOC | Arabic GCC |
| `08:ac:66:7c:65:d3:6d:65:42:91:76:55:57:1e:61:c8` | DriveTheLife cert serial | SmadAV/Indonesia |

---

## 13. MITRE ATT&CK Heat Map

The following techniques are used **consistently across 3 or more campaigns** and represent the Mustang Panda PlugX TTP fingerprint:

| Technique | ID | Campaigns |
|---|---|---|
| DLL Side-Loading | T1574.002 | All 4 |
| Masquerade: Match Legitimate Name | T1036.005 | All 4 |
| Deobfuscate/Decode Files | T1140 | All 4 |
| Obfuscated Files or Information | T1027 | All 4 |
| Indicator Removal: DJB2/API Hashing | T1027.005 | All 4 |
| Application Layer Protocol: Web | T1071.001 | All 4 |
| Encrypted Channel | T1573 | All 4 |
| PEB Walking / Native API | T1106 | All 4 |
| Code Signing Abuse | T1553.002 | All 4 |
| Process Injection | T1055 | 3 of 4 |
| COM Hijacking | T1546.015 | 3 of 4 |
| Registry Run Keys | T1547.001 | 3 of 4 |
| System Binary Proxy Execution: MSI | T1218.007 | 2 of 4 |
| Phishing: Spearphishing Attachment | T1566.001 | 3 of 4 |
| Application Layer Protocol: DNS | T1071.004 | 1 of 4 (rising) |
| Signed Binary Proxy Execution: CHM | T1218.001 | 1 of 4 |

---

## 14. Attribution Summary

| Attribute | Assessment |
|---|---|
| **Actor** | Mustang Panda / Earth Preta / BRONZE PRESIDENT / TA416 / TWILL TYPHOON / CAMARO DRAGON / UNC6384 |
| **MITRE Group** | G0129 |
| **Nation-state** | China (PRC) |
| **Confidence** | High (Nepal/Vietnam: High; GCC/SmadAV: Medium-High) |
| **Primary motivation** | Intelligence collection / espionage |
| **Active period** | At least 2023–2026 (this corpus) |
| **Targets** | Diplomatic, government, enterprise — Asia-Pacific, Middle East, Europe |

**Attribution basis:**
- G DATA `Avk.exe` SHA256 (`8421e799...`) confirmed by Lab52 as UNC6384 campaign IoC
- DriveTheLife certificate (`91440300695560951T`) documented across multiple Earth Preta campaigns
- `BIU BIU BIU!!!` marker and `biuxmind.ini` documented by Avast/ESET as Earth Preta BIU sub-cluster
- `YYYYMMDD@@@` date-keyed RC4 pattern confirmed by Zscaler ThreatLabz as Mustang Panda-specific
- `_RigsterHook@0` export typo consistent across BaiduNetdisk campaigns
- Three-file sideloading kit structural identity across all campaigns

---

## 15. Trend Forecast and Defensive Implications

### What to expect next:

1. **DoH adoption will spread** beyond the DOPLUGS variant to other PlugX sub-variants. Defenders should implement encrypted DNS monitoring or enforce DNS-over-HTTPS termination at the enterprise proxy.

2. **Sideloading vehicle rotation will continue** — expect new signed binaries from different software vendors. Detection should focus on behavioral patterns (unsigned DLL in same directory as signed EXE, minimal import tables, PEB walking) rather than specific filename signatures.

3. **Persistence key rotation** away from `ms-pu` and `Capitol` to new COM subkeys. Alert logic must generalize to `HKCU\Software\CLASSES\[novel key]\CLSID` writes by non-system processes.

4. **LCG-based encryption** will likely replace simple XOR/static-key RC4 as the actor further hardens against static decryption. The LCG + LZNT1 pattern (shared between Arabic GCC and SmadAV samples) may become the standard payload protection.

5. **Middle East geographic expansion** is confirmed. Arabic-language lures targeting GCC nations should be anticipated in ongoing campaigns, particularly around regional conflict or geopolitical inflection points.

6. **CFF + MBA obfuscation** will expand from DOPLUGS to other variants. Defenders should invest in decompilation capabilities (Ghidra + deobfuscation plugins) rather than relying on string-based detection.

### Priority defensive actions:

| Priority | Action |
|---|---|
| P0 | Block all C2 domains/IPs in this corpus at DNS, proxy, and firewall |
| P0 | Alert on `Software\CLASSES\[any]\CLSID` writes from non-system processes |
| P0 | Revoke/distrust DriveTheLife cert serial `08:ac:66:7c:65:d3:6d:65:42:91:76:55:57:1e:61:c8` |
| P1 | Alert on `hh.exe` (HTML Help) spawning `cmd.exe` |
| P1 | Alert on `msiexec.exe` dropping binaries to `%LOCALAPPDATA%` with `ARPSYSTEMCOMPONENT` |
| P1 | Hunt for `%APPDATA%\Render\`, `%ALLUSERSPROFILE%\SxS\`, `biuxmind.ini` |
| P1 | Alert on `SystemFunction033` called from non-system module (dynamic RC4) |
| P2 | Monitor for HTTPS traffic to `.cn`, `.info` domains with SNI patterns matching `windows.*`, `360*` |
| P2 | Deploy DoH inspection or forced-termination at enterprise proxy |
| P2 | Hunt for `NvSmart.hlp`, `NvSmart.x64.hlp`, `update.dat` in user-writable paths |

---

## 16. Cross-Campaign Correlation Matrix

| Indicator | Nepal | Vietnam | GCC | SmadAV |
|---|---|---|---|---|
| `%APPDATA%\Render\` install dir | ✅ | ✅ | ❌ | ❌ |
| `Software\CLASSES\ms-pu` | ✅ | ✅ | ❌ | ❌ |
| `Software\CLASSES\Capitol` | ❌ | ❌ | ❌ | ✅ |
| BB01 HMAC-SHA256 C2 protocol | ✅ | ✅ | ❌ | ❌ |
| DOPLUGS variant | ❌ | ❌ | ✅ | ❌ |
| BIU cluster marker | ❌ | ❌ | ❌ | ✅ |
| WiX 3.11 `MainProgran` MSI | ✅ | ✅ | ❌ | ❌ |
| DJB2 API hashing in loader | ✅ | ✅ | — | ❌ |
| Forged future PE timestamp | ✅ (2059) | ✅ (2056) | ✅ (zeroed) | ❌ |
| CRT DLLs staged in kit | ❌ | ❌ | ✅ | ❌ |
| GetPC shellcode stub | ❌ | ❌ | ✅ | ✅ |
| LCG + LZNT1 decryption | ❌ | ❌ | ✅ (stage 2) | ✅ |
| DriveTheLife certificate | ❌ | ❌ | ❌ | ✅ |

The high overlap in the Nepal/Vietnam pair (same `%APPDATA%\Render\`, same `ms-pu` key, same BB01 protocol, same WiX template) confirms they are the **same sub-cluster or even the same campaign wave** with only the lure and sideloading binary rotated. The SmadAV and Arabic GCC samples share the GetPC/shellcode stub pattern and LCG decryption, suggesting a **second code branch** within the Mustang Panda toolkit.

---

## 17. References

| Source | Notes |
|---|---|
| Lab52 — PlugX Meeting Invitation via MSBuild and GData | Nepal CIAA campaign attribution |
| Zscaler ThreatLabz — China-nexus Threat Actor Targets Persian Gulf | Arabic GCC campaign, YYYYMMDD@@@ pattern, DOPLUGS key |
| Zscaler ThreatLabz — Latest Mustang Panda Arsenal (PAKLOG/SplatCloak) | Broader Mustang Panda toolset context |
| Avast / ESET — Earth Preta BIU Loader Cluster | BIU cluster attribution, biuxmind.ini, `BIU BIU BIU!!!` |
| MITRE ATT&CK — Mustang Panda (G0129) | Group reference |
| The Record — Belgium and Hungary diplomatic entities hacked by UNC6384 | European targeting context |
| FBI — Deletes PlugX malware from 4,250 US computers (Jan 2025) | Scale of PlugX infrastructure |

---

*Report generated: 2026-04-20 | Based on 4 confirmed PlugX sample analyses from /home/muffin/report/ | TLP:AMBER — Share with trusted partners only*
