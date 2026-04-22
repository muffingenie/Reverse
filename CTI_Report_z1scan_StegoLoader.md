# CTI Report: Multi-Stage Steganographic .NET Loader
**Filename:** `z1scan_copy_3486180358.bat` + `file.dat`  
**Date:** 2026-04-21  
**Analyst:** REMnux Static Analysis  
**Confidence:** High (static; no sandbox execution)  
**TLP:** TLP:AMBER

---

## Executive Summary

Two files were recovered from the REMnux samples directory: a **875 KB executable disguised as a batch script** (`z1scan_copy_3486180358.bat`) and a **1 KB custom-encoded blob** (`file.dat`). The .bat file is a **three-stage steganographic .NET loader** that hides a 67 KB malicious .NET DLL inside an embedded BMP image using pixel channel (R/G/B) steganography. The second-stage DLL was compiled on the day of analysis (2026-04-21 00:51:49 UTC), carries heavy Georgian-alphabet control flow obfuscation and anti-analysis attributes, and is designed to fetch a remotely hosted bitmap, extract a Stage 3 payload from it, and execute it in memory via `Assembly.Load()`. No network IOCs (C2 URLs) were recovered statically due to runtime string decoding; the Stage 3 payload remains unknown pending dynamic analysis or network capture.

The `file.dat` artefact (1001 bytes, byte range 0–100) is a custom-encoded blob consistent with the CK1.0 RAT investigation environment; its encoding scheme was not fully recovered statically.

---

## 1. Sample Inventory

| Role | Filename | SHA-256 | SHA-1 | MD5 | Size |
|------|----------|---------|-------|-----|------|
| Stage 1 loader (fake .bat) | `z1scan_copy_3486180358.bat` | `346627d7d58703c3da5b604372778175219e5f7f8c0998f742ebede838fa79e4` | `65c13adfffd73473f400a933175f236a890dcd1c` | `a0eba195bef0cb949f8f5e7359e7595f` | 875,008 B |
| Stego BMP carrier (embedded) | `Disk` resource (extracted) | `7538e8c03fd49524b32706ea480be79d6ea9427a58ec2831f93671233d48e7e9` | `0308a439abf95fa9383a8789d5ef7074cc3271ef` | `5ed09cc2768038e154f6b0933ddcb02b` | 91,258 B |
| Stage 2 DLL (stego-extracted) | `extracted_z1scan_payload.bin` | `2b982a856df29ba12dc5a81e5a19d6b7e106f5f6f7ce3baeff263497afe732ec` | `fb578cbae4a51d6dceb5ae3dc358f56066a97259` | `f6782553574488ead1c850b1368f6183` | 67,072 B |
| Unrelated encoded blob | `file.dat` | `bfaf5aa667e151c68d22cedc0e05ac068037f64151fdc64e4ff775465bd619d7` | `68f321334c30e4689fd94e2d539b6d63ebf81bed` | `fe5de2f2bc22ac01839b0df6ea71ac24` | 1,001 B |

---

## 2. Stage 1 Analysis — `z1scan_copy_3486180358.bat`

### 2.1 File Characteristics

| Field | Value |
|-------|-------|
| True type | PE32 executable (.NET assembly, GUI) |
| Extension | `.bat` (masquerade) |
| .NET framework | v4.5 |
| Architecture | x86 (i386) |
| Timestamp | **Forged**: 2104-04-10 (`0xFC900D98`) |
| Namespace | `MagnetosphereSimulator` |
| Assembly GUID | `9480e501-c861-4e5d-91c1-8545ca3243e2` |
| Sections | `.text` (877,568 B), `.rsrc` (2,560 B), `.reloc` (512 B) |

### 2.2 Fake Assembly Metadata

All assembly metadata is falsified to deflect triage:

| Field | Fake Value |
|-------|-----------|
| AssemblyTitle | `PDF FILE PREVIEWER Google Translation DESKTOP OPENNER` |
| AssemblyCompany | `PDF FILE PREVIEWER Google Translation DESKTOP OPENNER` |
| AssemblyCopyright | `PDF FILE PREVIEWER Google Translation DESKTOP OPENNER COPYRIGHT 2011 FOR xIMUsOFT.` |
| AssemblyProduct | `PDF FILE PREVIEWER Google Translation DESKTOP OPENNER` |
| AssemblyTrademark | `...TRADEMARK 2011 FOR xIMUsOFT` |

**`xIMUsOFT`** appears to be a recurring threat-actor handle or fake company name.

### 2.3 Cultural Indicators

The `MagnetosphereEngine` class uses **Traditional Chinese** identifiers throughout:

| Identifier | Meaning |
|-----------|---------|
| `場向量` | Field vector |
| `太陽風狀態` | Solar wind state |
| `粒子種類` | Particle type |
| `粒子軌跡` | Particle trajectory |
| `引擎` | Engine |
| `游標` | Cursor |
| `視窗` | Window |

This strongly indicates a **Mandarin-speaking developer** (Traditional Chinese script = Taiwan/Hong Kong/Overseas Chinese diaspora preference, though simplified script users sometimes mix).

### 2.4 Signature Blob

```csharp
private static readonly byte[] 簽_BLOB = new byte[12] {
    34, 102, 104, 113, 104, 119, 111, 115, 105, 101, 115, 102
};
// Decoded: "fhqhwosiesf (with leading quote)
// Used to compute GetSignature() status bar string via obfuscated XOR transform
```

### 2.5 Auth String (Credential/Key Passing Mechanism)

```csharp
private readonly string Auth =
    "574F7761MagnetosphereSimulator626765MagnetosphereSimulator";
```

At runtime this is split on `"MagnetosphereSimulator"` to yield three components:
- `array[0]` = `"574F7761"` → hex-decoded = **`"WOwa"`**
- `array[1]` = `"626765"` → hex-decoded = **`"bge"`**
- `array[2]` = `"MagnetosphereSimulator"` (marker string)

These three strings are passed as constructor arguments to the Stage 2 DLL.

### 2.6 Steganographic Payload Extraction (`DrainVaultSequence`)

The loader extracts a 67,072-byte payload from the embedded 151×151 BMP resource named `Disk`:

```
Algorithm: column-major pixel traversal (x outer, y inner)
Per pixel:  append pixel.R, then pixel.G, then pixel.B (with drainLimit check after each)
drainLimit: 67,072 bytes
Source:     Resources.Disk (91,258 B BMP, 151×151 px, 24-bit colour)
Capacity:   151 × 151 × 3 = 68,403 bytes maximum
Extracted:  67,072 bytes (fills 97.9% of image capacity)
```

Guard conditions (all must be true to extract — all evaluate true with default params):
- `flag = (num ^ 0xDEAD) != 0xDEAD` → true when calibrationToken yields non-zero XOR hash
- `!flag2` → true when bitmap stride × height < `int.MaxValue`
- `text != null` → always true
- `num8 >= 0f` → RMS of oscillation array, always ≥ 0
- `num21 <= 1.0` → Gaussian peak/sum ratio, always ≤ 1

### 2.7 In-Memory Payload Execution

```csharp
// pf = DrainVaultSequence(Resources.Disk, 67072) — called from constructor
Assembly assembly = Interaction.CallByName(
    Thread.GetDomain(), "Load", CallType.Method,
    new object[] { Enumerable.ToArray(pf) }) as Assembly;

Type type = assembly.GetExportedTypes()[0];
object obj = ObjectFactory.Create(type, new[] { "574F7761", "626765", "MagnetosphereSimulator" });
```

The Stage 2 DLL is **never written to disk** — loaded entirely in memory via `AppDomain.Load(byte[])`.

### 2.8 Anti-Analysis

- `[SuppressIldasm]` NOT present in Stage 1 (present in Stage 2)
- Forged PE timestamp (2104)
- Analysis tool detection: CAPA confirmed `B0013.001 Analysis Tool Discovery::Process detection`
- Fake GUI application (functional magnetosphere simulator) providing legitimate-looking cover when opened

---

## 3. Stage 2 Analysis — `DiskMasterUltimate` (extracted_z1scan_payload.bin)

### 3.1 File Characteristics

| Field | Value |
|-------|-------|
| True type | PE32 DLL (.NET assembly, console) |
| Timestamp | **2026-04-21 00:51:49 UTC** (same day as analysis — freshly compiled) |
| Architecture | x86 (i386) |
| .NET framework | v4.x |
| Assembly GUID | `C9E7A5F8-6D4B-4A3E-9F2C-8B1A7D6E5F4C` |
| Sections | `.text` (64,512 B), `.rsrc` (1,536 B), `.reloc` (512 B) |

### 3.2 Fake Assembly Metadata

| Field | Value |
|-------|-------|
| AssemblyTitle | `DiskMaster Ultimate` |
| AssemblyProduct | `DiskMaster Ultimate` |
| AssemblyCompany | `StorageVault Technologies` |
| AssemblyDescription | `Enterprise-grade storage virtualization and partition management platform` |
| AssemblyCopyright | `Copyright © StorageVault Technologies 2025` |
| AssemblyTrademark | `DiskMaster™` |
| AssemblyConfiguration | `Enterprise` |
| AssemblyVersion | `15.8.3.0` / FileVersion `15.8.3.7924` |

### 3.3 Obfuscation

Stage 2 employs **four overlapping obfuscation techniques**:

#### 3.3.1 Georgian Unicode Identifiers
All class, method, field, and namespace names use Georgian script characters (`Ⴀ–Ⴠ`, `ⴀ–ⴠ`):
```
Namespaces: Ⴅ, Ⴍ, Ⴓ
Classes:    ႤႤ, ႷႰ, ႨႨ, ႳႭ, ႨႷ, ႨႳ, ႨႭ
```

#### 3.3.2 Control Flow Flattening
Switch-case state machines driven by a **260-element opaque integer table** (`ႤႤ.Ⴀ`) initialized at module load:
```csharp
ႤႤ.Ⴀ = new int[260] { 64919, 40486, 61411, 17603, ... }
```
Actual control flow: `num = ⴀ[207] - 6920; switch(num) { ... }`

#### 3.3.3 Opaque Predicates via 328-Byte Key Array
A 328-byte array (`MultiTabCalculatorForm.Ⴗ`) provides both opaque predicates and key material:
```csharp
// Example opaque predicate (always yields same result):
Ⴗ[326] = (byte)((Ⴗ[326] - Ⴗ[53]) & 0x8C);
Ⴗ[48] = (byte)((Ⴗ[48] + Ⴗ[298]) & 0xB0);
```

#### 3.3.4 Anti-Disassembly Attribute
```csharp
[assembly: SuppressIldasm]
```

### 3.4 Constructor Flow

```csharp
public MultiTabCalculatorForm(
    string EnumCategoriesFlags,  // = "574F7761" → hex → "WOwa"
    string DataMisaligned,       // = "626765"  → hex → "bge"
    string DirectoryInfo)        // = "MagnetosphereSimulator"
```

A cover `Dictionary<string, double>` of unit conversion factors (mm, cm, m, km, inch, foot, yard, mile: 0.001, 0.01, 1.0, 1000.0, 0.0254, 0.3048, 0.9144, 1609.344) is initialized to simulate a calculator application.

### 3.5 Stage 3 Loading Chain

```
CausalitySource("574F7761") → hex decode → "WOwa"   [bitmap resource name]
CausalitySource("626765")   → hex decode → "bge"    [resource namespace prefix]

LowestBreakIteration("WOwa", "bge")
  └─ ResourceManager("bge" + <decoded_suffix>, <obfuscated_assembly_ref>)
       .GetObject("WOwa")
  └─ Returns: Bitmap (remotely fetched or satellite resource)

RestoreOriginalBitmap(bitmap, addedWidth=177, addedHeight=225)
  └─ Crops bitmap by (177, 225) to recover original dimensions
  └─ Extracts ARGB pixel data as byte stream

ႳႭ(cropped_bitmap)
  └─ Reads GetPixel() values, returns byte[]

Ⴓ.Ⴜ.Ⴃ(byte[], 'Đ', 348)  ≡  AppDomain.Load(byte[])
  └─ Loads Stage 3 .NET assembly in memory

global::Ⴍ.ႥႥ.Ⴃ(assembly.GetExportedTypes()[20 or 15], 978, 1001)[idx]
  .Invoke(null, null)
  └─ Executes static entry point of Stage 3 payload
```

**Key insight**: `RestoreOriginalBitmap` uses `addedWidth=177`, `addedHeight=225` as offsets, suggesting the remote carrier image has been padded with 177 extra columns and 225 extra rows to disguise its true dimensions from image-aware defenses.

### 3.6 Decryption Utility (`Mist`)

```csharp
public static byte[] Mist(byte[] fog, string kite)
```
- Takes last byte of `fog` XOR `0x70` as an integer parameter  
- `kite` key passed via `ႳႣ(kite)` which calls `Encoding.GetBytes(kite)`  
- This is likely the XOR/RC4 decryption routine for Stage 3 payload decryption  
- Key material derived from the `"WOwa"` / `"bge"` arguments

### 3.7 CAPA Results

| ATT&CK | Technique | MBC |
|--------|-----------|-----|
| Defense Evasion | T1620 Reflective Code Loading | — |
| — | — | C0055 Suspend Thread |
| — | — | C0018 Terminate Process |
| — | Access .NET resource | — |
| — | Load .NET assembly | — |
| — | Invoke .NET assembly method | — |

---

## 4. `file.dat` Analysis

### 4.1 Characteristics
- Size: 1,001 bytes
- Entropy: 6.58 bits/byte (moderately high)
- Byte range: **0x00–0x64 (0–100 decimal)** — strongly constrained; not consistent with raw binary data or standard XOR cipher output
- 101 distinct byte values
- File type: `data` (unrecognised by `file`)
- Date: 2026-04-18 (same date as CK1.0 RAT artefacts `T3a05616`, `backup.exe.bin`)

### 4.2 Encoding Analysis

| Transform | Printable % | Assessment |
|-----------|-------------|-----------|
| Raw | — | Non-printable |
| XOR `0x6e` | **94.4%** | Strong candidate; yields partial `"sam-4"` prefix |
| XOR `0x0b` | 71.6% | Weaker match |
| +32 offset | ~60% | Some readable tokens, not clean |

The 0x00–0x64 byte range with XOR `0x6e` giving 94.4% printable is consistent with CK1.0 RAT's known XOR key (`0x6e`). However, the decoded output is not cleanly structured text, suggesting a **secondary layer** (additional encoding, compression, or protocol framing) on top of XOR `0x6e`.

Decoded prefix (XOR `0x6e`): `sam-4` followed by mixed printable/control-character data. Possible interpretations:
- Network beacon capture with binary length prefixes
- Config blob with mixed binary fields
- Custom base-101 alphabet encoding with XOR obfuscation

**Assessment**: Likely a network communication capture or config fragment from the CK1.0 RAT (`106.54.39.113`) investigation; encoding not fully recovered statically.

---

## 5. Indicators of Compromise (IOCs)

### 5.1 File Hashes

| Hash | Value | Description |
|------|-------|-------------|
| SHA-256 | `346627d7d58703c3da5b604372778175219e5f7f8c0998f742ebede838fa79e4` | Stage 1 loader (.bat masquerade) |
| MD5 | `a0eba195bef0cb949f8f5e7359e7595f` | Stage 1 loader |
| SHA-256 | `2b982a856df29ba12dc5a81e5a19d6b7e106f5f6f7ce3baeff263497afe732ec` | Stage 2 DLL (DiskMasterUltimate) |
| MD5 | `f6782553574488ead1c850b1368f6183` | Stage 2 DLL |
| SHA-256 | `7538e8c03fd49524b32706ea480be79d6ea9427a58ec2831f93671233d48e7e9` | Stego BMP carrier (Disk resource) |
| SHA-256 | `bfaf5aa667e151c68d22cedc0e05ac068037f64151fdc64e4ff775465bd619d7` | file.dat (CK1.0 context) |

### 5.2 .NET Assembly GUIDs

| GUID | Assembly |
|------|----------|
| `9480e501-c861-4e5d-91c1-8545ca3243e2` | Stage 1 (MagnetosphereSimulator) |
| `C9E7A5F8-6D4B-4A3E-9F2C-8B1A7D6E5F4C` | Stage 2 (DiskMasterUltimate) |

### 5.3 String IOCs

| String | Location | Significance |
|--------|----------|-------------|
| `xIMUsOFT` | Stage 1 metadata | Threat actor handle / fake company |
| `MagnetosphereSimulator` | Stage 1 namespace, Auth delimiter | Internally unique marker |
| `DiskMasterUltimate` | Stage 2 namespace | Internally unique marker |
| `StorageVault Technologies` | Stage 2 metadata | Fake company name |
| `574F7761MagnetosphereSimulator626765MagnetosphereSimulator` | Stage 1 Auth field | Authentication/key transport string |
| `fhqhwosiesf` | Stage 1 `簽_BLOB` (decoded) | Signature token |
| `WOwa` / `bge` | Decoded auth args | Stage 3 bitmap resource name / namespace |
| `63B87CA1301DCE354D7C34BBEBA1535D9FA9A0514D923A5FE609F871BEDEBA62` | Stage 2 strings | Embedded SHA-256 (expected hash of Stage 3?) |
| `CAL-000` | DrainVaultSequence default | Calibration token for stego extraction |

### 5.4 Network IOCs

**None recovered statically.** Stage 2 decodes all strings at runtime via the 260-int CFG table. Dynamic analysis or sandbox detonation required to recover:
- Stage 3 bitmap host URL
- Satellite assembly download path
- Any C2 infrastructure

### 5.5 Filesystem Artefacts

No explicit persistence, dropped files, or registry keys identified in Stage 1 or Stage 2. Stage 3 functionality unknown. Execution is entirely in-memory (fileless).

---

## 6. MITRE ATT&CK TTPs

| Technique | ID | Implementation |
|-----------|-----|----------------|
| Masquerading: Invalid File Extension | T1036.007 | Stage 1 is PE32 EXE distributed with `.bat` extension |
| Masquerading: Rename System Utilities | T1036.003 | Fake "PDF FILE PREVIEWER" / "DiskMaster Ultimate" metadata |
| Obfuscated Files or Information: Steganography | T1027.003 | 67 KB payload hidden in BMP pixel R/G/B channels |
| Obfuscated Files or Information: Embedded Payloads | T1027.009 | Stage 2 DLL embedded in Stage 1 .NET resource `Disk` |
| Obfuscated Files or Information: Software Packing | T1027.002 | Georgian-alphabet renaming, CFG flattening, opaque predicates |
| Deobfuscate/Decode Files or Information | T1140 | `CausalitySource()` hex-decodes runtime strings; `DrainVaultSequence()` extracts payload |
| Reflective Code Loading | T1620 | `AppDomain.Load(byte[])` for Stage 2; `Ⴓ.Ⴜ.Ⴃ(byte[])` for Stage 3 |
| Ingress Tool Transfer | T1105 | Stage 2 fetches Stage 3 bitmap from remote resource (URL not recovered) |
| Indicator Removal: Timestomping | T1070.006 | Stage 1 PE timestamp forged to 2104-04-10 |
| Hide Artifacts: Process Argument Spoofing | T1564.010 | Auth string split by marker to obscure key material in static analysis |

---

## 7. Detection Rules

### 7.1 YARA — Stage 1 Loader

```yara
rule STEGO_NET_Loader_z1scan_Stage1
{
    meta:
        description = "Detects z1scan MagnetosphereSimulator steganographic .NET loader"
        author      = "CTI Analysis"
        date        = "2026-04-21"
        hash        = "346627d7d58703c3da5b604372778175219e5f7f8c0998f742ebede838fa79e4"
        tlp         = "AMBER"

    strings:
        $guid       = "9480e501-c861-4e5d-91c1-8545ca3243e2" ascii wide
        $auth       = "574F7761MagnetosphereSimulator626765MagnetosphereSimulator" ascii wide
        $stego_func = "DrainVaultSequence" ascii wide
        $fake_meta  = "xIMUsOFT" ascii wide
        $sig_blob   = "fhqhwosiesf" ascii wide
        $trad_cn_1  = { E5 A0 B4 E5 90 91 E9 87 8F }  // 場向量 UTF-8
        $trad_cn_2  = { E5 A4 AA E9 99 BD E9 A2 A8 E7 8B 80 E6 85 8B }  // 太陽風狀態 UTF-8

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($guid, $auth, $stego_func, $fake_meta, $sig_blob)) or
        (any of ($trad_cn_1, $trad_cn_2))
}
```

### 7.2 YARA — Stage 2 DLL (DiskMasterUltimate)

```yara
rule STEGO_NET_Payload_DiskMasterUltimate_Stage2
{
    meta:
        description = "Detects DiskMasterUltimate obfuscated .NET Stage 2 stego payload"
        author      = "CTI Analysis"
        date        = "2026-04-21"
        hash        = "2b982a856df29ba12dc5a81e5a19d6b7e106f5f6f7ce3baeff263497afe732ec"
        tlp         = "AMBER"

    strings:
        $guid        = "C9E7A5F8-6D4B-4A3E-9F2C-8B1A7D6E5F4C" ascii wide
        $company     = "StorageVault Technologies" ascii wide
        $namespace   = "DiskMasterUltimate" ascii wide
        $method_1    = "LowestBreakIteration" ascii wide
        $method_2    = "RestoreOriginalBitmap" ascii wide
        $method_3    = "CausalitySource" ascii wide
        $method_4    = "DrainVaultSequence" ascii wide
        $embedded_h  = "63B87CA1301DCE354D7C34BBEBA1535D9FA9A0514D923A5FE609F871BEDEBA62" ascii wide
        $suppress    = "SuppressIldasm" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        3 of them
}
```

### 7.3 YARA — Steganographic BMP Carrier (Generic)

```yara
rule Stego_BMP_NET_Payload_Carrier
{
    meta:
        description = "BMP image carrying .NET assembly payload in pixel RGB channels (column-major)"
        note        = "Match on BMP containing MZ header reconstructable from RGB columns"

    strings:
        $bmp_magic = { 42 4D }
        // First pixel column R=0x4D G=0x5A (MZ), second col R=0x90 G=0x00 B=0x00
        // Third col R=0x03 ... etc — specific to this variant
        $mz_in_rgb = { 4D 00 00 5A 00 00 90 00 00 00 00 00 03 00 00 00 }

    condition:
        uint16(0) == 0x424D and
        filesize > 50000 and filesize < 500000 and
        $mz_in_rgb at 54  // after 54-byte BMP header
}
```

### 7.4 Sigma — Suspicious .bat File Executing as PE

```yaml
title: BAT File Containing PE/MZ Header Executed
id: a3f21d40-8b9e-4c72-a18d-c6e5b1d7f302
status: experimental
description: Detects execution of .bat files that are actually PE executables (extension masquerade)
author: CTI Analysis
date: 2026-04-21
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '.bat'
        CommandLine|contains:
            - '.bat'
    filter_legit:
        Image|startswith:
            - 'C:\Windows\System32\cmd.exe'
            - 'C:\Windows\SysWOW64\cmd.exe'
    condition: selection and not filter_legit
falsepositives:
    - None expected
level: high
tags:
    - attack.defense_evasion
    - attack.t1036.007
```

### 7.5 Sigma — In-Memory .NET Assembly Loading Chain

```yaml
title: .NET AppDomain.Load Reflective Assembly Execution
id: b8c4e2f1-9a3d-4b57-8c12-d7e5f6a3b209
status: experimental
description: Detects .NET assembly loading from byte array in memory (fileless execution)
author: CTI Analysis
date: 2026-04-21
logsource:
    product: windows
    category: process_creation
detection:
    selection_clr:
        # ETW Microsoft-Windows-DotNETRuntime: AssemblyLoad event
        # EventID 154 = Assembly Load
        EventID: 154
        AssemblyName|contains:
            - 'DiskMasterUltimate'
            - 'MagnetosphereSimulator'
    condition: selection_clr
falsepositives:
    - None expected for these specific assembly names
level: critical
tags:
    - attack.defense_evasion
    - attack.t1620
```

---

## 8. Attribution Assessment

**Confidence: Low–Medium**

| Indicator | Assessment |
|-----------|-----------|
| Traditional Chinese identifiers | Mandarin-speaking developer; Traditional Chinese script preference (Taiwan/HK/diaspora) vs. Simplified (PRC mainland) — inconclusive for nation attribution |
| `xIMUsOFT` fake company | Not previously attributed; may be new cluster or recycled persona |
| Fresh compile timestamp (2026-04-21 00:51:49 UTC) | Active development as of analysis date |
| Multi-stage stego loader architecture | TTP overlap with Chinese-nexus APT tradecraft (compare CHM sample with BaiduNetdisk sideloading, Shelter.ex stego from same environment) |
| `MagnetosphereSimulator` / `DiskMasterUltimate` covers | Novel tool families, not previously publicly documented |
| SHA-256 `63B87CA1301...` embedded in Stage 2 | Likely expected hash of Stage 3; could be used for C2 verification or signed payload validation |

**Assessment**: This loader is consistent with **Chinese-nexus APT tradecraft** based on: Traditional Chinese identifier language, multi-stage steganographic .NET loader architecture overlapping with other samples in this investigation environment, and heavy obfuscation with anti-analysis measures. **Attribution to a specific group (Mustang Panda, APT41, etc.) is NOT supported** by current evidence — this may be a distinct sub-cluster or a new tool family.

---

## 9. Recommended Actions

1. **Block hashes** (SHA-256 Stage 1 and Stage 2) in EDR/AV and threat intel platforms immediately.
2. **Detonate in sandbox** (Any.Run / Triage / Cape) to recover:
   - Stage 3 URL (network capture)
   - Stage 3 payload identity and capabilities
   - C2 infrastructure
3. **Hunt for `DrainVaultSequence` / `LowestBreakIteration` / `CausalitySource` method names** across .NET assemblies in your environment via EDR script/YARA.
4. **Monitor ETW DotNETRuntime AssemblyLoad events** for `DiskMasterUltimate` or `MagnetosphereSimulator` assembly names.
5. **Flag `.bat` files > 100 KB** for PE header check — legitimate batch scripts are never > a few KB.
6. **Correlate `xIMUsOFT`** against threat intel databases and hunting queries for prior appearances.
7. **Analyse `file.dat`** dynamically in CK1.0 RAT execution context to determine if it is a live beacon capture.

---

## 10. Limitations

- **No Stage 3 payload recovered**: `LowestBreakIteration` fetches the Stage 3 carrier from a runtime-decoded URL; static analysis cannot reconstruct it. Dynamic execution required.
- **No network IOCs**: All C2 strings are runtime-decoded; no domains, IPs, or URLs identified statically.
- **file.dat encoding unresolved**: Custom byte-constrained encoding scheme not definitively identified without the CK1.0 RAT binary context.
- **Stage 2 obfuscation limits**: The 260-int CFG table and Georgian obfuscation prevent full semantic recovery of all functions; `Ⴍ.ႥႤ.Ⴄ()`, `Ⴍ.Ⴗ()`, `Ⴓ.Ⴜ.Ⴐ()` etc. are obfuscation framework stubs whose resolved values require runtime tracing.
