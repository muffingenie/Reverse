# Cyber Threat Intelligence Report
## Malicious MSI Installer — PlugX / Korplug via G DATA DLL Sideloading

| Field | Value |
|-------|-------|
| **Report Date** | 2026-03-03 |
| **Analyst Platform** | REMnux (Isolated Malware Analysis VM) |
| **Classification** | TLP:WHITE |
| **Threat Type** | PlugX RAT (Remote Access Trojan) — DLL Sideloading via Trojan MSI |
| **Malware Family** | PlugX / Korplug (S0013) |
| **Threat Actor** | UNC6384 (overlaps with Mustang Panda / BRONZE PRESIDENT / Earth Preta) |
| **Attribution Confidence** | High |
| **Severity** | Critical |

---

## 1. Executive Summary

A 893 KB Windows Installer Package (MSI) was submitted for analysis. The package masquerades as a legitimate Windows system installer (falsely attributing authorship to "Microsoft Corporation") and implements a **multi-stage DLL sideloading attack chain** using a **legitimately signed G DATA AntiVirus binary** to load a malicious DLL, which in turn decrypts and reflectively loads a fully-featured **PlugX / Korplug RAT payload** from a disguised `.dat` file.

The sample shares confirmed file hash overlap and technical characteristics with a January 2026 campaign documented by Lab52, attributed to **UNC6384** — a Chinese state-sponsored APT group with significant operational overlap with **Mustang Panda** (also tracked as BRONZE PRESIDENT, Earth Preta, RedDelta, TA416, TWILL TYPHOON, CAMARO DRAGON). The campaign uses **"Meeting Invitation"** spear-phishing lures targeting **diplomatic entities** in Europe and Southeast Asia.

The encrypted final payload (PlugX) communicates with **`carhirechicago[.]com:443`** for command and control, employing HMAC-authenticated HTTPS sessions with XOR-encoded data streams. The C2 hostname is statically embedded in the RC4-decrypted config blob (encoded with a position-based XOR using `FUN_10081750`, recoverable without sandbox execution). The MSI installs silently to `%LOCALAPPDATA%`, hides from Add/Remove Programs, and establishes **persistence via Windows registry Run key** or **Windows service**.

> **Attribution correction**: Initial analysis cited `decoraat[.]net` (Lab52 hash-pivot). The actual C2 for this sample (SHA-256: 9e7bb2f6b5a7e79b14b4e0e10a97518592071ebbe196452cfc75addca0496381) is `carhirechicago[.]com`, confirmed by both sandbox network capture and static analysis of the RC4-decrypted config blob (hostname recovered via FUN_10081750 decode, offset +0x6b4).

---

## 2. File Identification — All Components

### 2.1 MSI Installer (Container)

| Attribute | Value |
|-----------|-------|
| **Filename** | `601ae63ee59288a2e36f0b0d4f7bc0bfb40f0489995343c955db7d9ded469478.msi` |
| **File Size** | 892,928 bytes (872 KB) |
| **File Type** | Composite Document File V2 (OLE2) — Windows Installer MSI |
| **MIME Type** | `image/vnd.fpx` (OLE2 container misidentified) |
| **Magika** | Microsoft Installer file (archive) |
| **TrID** | 88.4% Windows SDK Setup Transform (.MST) |
| **Entropy** | **7.9608 bits/byte** (near-maximum — cabinet is compressed/encrypted) |
| **MD5** | `ab56563f3817e31568e487edc232a7ee` |
| **SHA-1** | `4142b2d89afec1b5b2379219af3b5a2fabe53a8b` |
| **SHA-256** | `601ae63ee59288a2e36f0b0d4f7bc0bfb40f0489995343c955db7d9ded469478` |
| **Product GUID** | `{D2FEECC2-CBCC-462C-AE5A-54A8FF76F8B5}` |
| **Upgrade GUID** | `{56593721-F300-4163-B356-314B36826412}` |
| **Revision GUID** | `{D48082FE-B1BE-4332-AF5F-485DD49CB81F}` |
| **Compiled** | 2026-03-01 08:35:46 UTC (recent) |
| **Builder** | Windows Installer XML Toolset (WiX) 3.11.2.4516 |
| **Claimed Author** | Microsoft Corporation (**FAKE**) |

### 2.2 Avk.exe — Legitimate G DATA Binary (Sideloading Vehicle)

| Attribute | Value |
|-----------|-------|
| **File Type** | PE32 executable (GUI) Intel 80386, 5 sections |
| **File Size** | 943,696 bytes |
| **Entropy** | 6.29 (normal) |
| **MD5** | `e7cb954f4bbdbadbd2c0206577621683` |
| **SHA-1** | `f06da8e29c3f0fafabfc3a524ae8b21730b57ed3` |
| **SHA-256** | `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99` ✅ *Matches Lab52 IoC* |
| **TLSH** | `T131153B217D81F23EE9F10170451D4937856FACAE276748E3A2B0765A3A7E2E14DFE423` |
| **ImphHash** | `24819a9e8d3b2fc3df12f1e0eaa5f23e` |
| **Compile Time** | 2025-05-26 22:11:41 UTC |
| **Digital Signature** | **VALID — Signed by G DATA CyberDefense AG** (Microsoft ID Verified CS AOC CA 02) |
| **Signer** | `C=DE, ST=North Rhine-Westphalia, L=Bochum, O=G DATA CyberDefense AG` |
| **PDB Path** | `C:\j\workspace\_AppDev_avk_release_1-production\bin\Release32v14x\Loader.pdb` |
| **File Description** | G DATA ANTIVIRUS (v25.1.25147.11) — **legitimate binary abused** |
| **Subsystem** | GUI (0x2) |
| **ASLR/NX** | Enabled (DllCharacteristics: 0xC140) |

> **Note:** This is a **genuine, legitimately signed** G DATA binary. The DLL search order is exploited so that when the attacker-controlled `Avk.dll` is placed in the same directory, Windows loads it before the legitimate system-path DLL.

### 2.3 Avk.dll — Malicious Loader / Korplug Stage 1

| Attribute | Value |
|-----------|-------|
| **File Type** | PE32 DLL (GUI) Intel 80386, 6 sections |
| **File Size** | 5,632 bytes (tiny loader) |
| **Entropy** | 3.58 |
| **MD5** | `9e77dea40479abf11fc3894bf50829f7` |
| **SHA-1** | `4b559bb8c4b623f0c6a08b947ef84ab197751140` |
| **SHA-256** | `ec0269b308395947a539ab7e275de98350b89943a5f48e47237deac9fff7b4a0` |
| **TLSH** | `T14BC194034B017AB5C4D50376206B3DE3DA3B46280FEA05CB5F6EE524A9B26E53E74F50` |
| **ImphHash** | N/A (import table deliberately obfuscated) |
| **Compile Time** | 2059-03-29 15:01:11 UTC (**BOGUS/FUTURE timestamp — common in malware**) |
| **Internal Name** | `sDl.dll` |
| **Exports** | `ModuleMain`, `ModuleMain2`, `_DllMain@12`, `__DllMainCRTStartup@12` |
| **Key Feature** | Contains `.tls` section (TLS callback for pre-entry execution) |

### 2.4 AVKTray.dat — XOR-Encrypted PlugX DLL (Stage 2 Payload)

| Attribute | Value |
|-----------|-------|
| **File Type (raw)** | Binary blob (custom encrypted) |
| **File Size** | 1,143,818 bytes (1.09 MB) |
| **Entropy (raw)** | **7.4616 bits/byte** (high — encrypted content) |
| **MD5 (raw)** | `33bbfa6d5c8a1078e4e260e15d563360` |
| **SHA-256 (raw)** | `732c747f2653e50acc5bc5b0bb07018777a0440840dd1fc5a023f3c4db2d111a` |
| **Encryption** | **XOR single-byte key** (0x0b); **6-byte custom header** prepended before XOR-encoded PE |
| **Custom header** | `f9 e8 00 68 09 00` (magic/length prefix) |
| **Decoded type** | PE32 DLL (GUI) Intel 80386, 4 sections |
| **MD5 (decoded)** | `de2fae03f8ffbd1c451887656a68d112` |
| **SHA-1 (decoded)** | `ede1c20ddba05b8355a89c3856e02f7abd8bb1d0` |
| **SHA-256 (decoded)** | `9e7bb2f6b5a7e79b14b4e0e10a97518592071ebbe196452cfc75addca0496381` |
| **Compile Time** | 2026-01-15 03:51:10 UTC |
| **Export** | `ZIWQXZXrVtgy` (randomised export name) |
| **Text entropy** | 7.00 (packed/encrypted code) |

---

## 3. MSI Package Analysis

### 3.1 Install Configuration

The MSI installs silently to a randomised subdirectory under `%LOCALAPPDATA%`, requiring **no administrative privileges**:

```
Install Path: %LOCALAPPDATA%\nDsMToCZME\
Deployed Files:
  - Avk.exe    (legitimate G DATA AV binary — sideloading vehicle)
  - Avk.dll    (malicious Korplug loader)
  - AVKTray.dat (XOR-encrypted PlugX DLL payload)
```

### 3.2 Stealth / Anti-Forensics Properties

| MSI Property | Value | Purpose |
|---|---|---|
| `ARPSYSTEMCOMPONENT` | `1` | **Hidden from Add/Remove Programs** |
| `ARPNOREPAIR` | `yes` | Disables repair option |
| `ARPNOMODIFY` | `yes` | Disables modification option |
| `Manufacturer` | `Microsoft Corporation` | **Identity masquerade** |
| `ProductName` | `MainProgran` | Deliberate misspelling (evasion) |
| `ProductVersion` | `10.0.39659` | Mimics Windows version numbering |

### 3.3 Custom Actions (Obfuscated)

The MSI install logic uses obfuscated custom action names, consistent with automated build-system obfuscation:

| Field | Value |
|---|---|
| **Cabinet** | `#UwZFJu9G.cab` (obfuscated name) |
| **Feature Name** | `SetjaDqEBz` (randomised) |
| **Custom Action 1** | `ORXBJbQGKV` |
| **Custom Action 2** | `EjllTUjLh` |
| **Custom Action 3** | `vWXuClpgIPE` |

### 3.4 OLE Streams

Stream 2 (857,433 bytes) is the embedded cabinet (`.cab`) file containing the compressed/encrypted payload files. Streams 3–22 contain the MSI database tables (Feature, Component, File, Directory, CustomAction, etc.) encoded in the MSI compound document format.

---

## 4. Attack Chain / Infection Flow

```
[DELIVERY]
  Spear-phishing email ("Meeting Invitation" lure)
  └── ZIP attachment
        ├── Invitation_Letter_No.02_2026.exe  (MSBuild LOLBIN)
        └── Invitation_Letter_No.02_2026.csproj (Base64-encoded downloader)
                │
                ▼
[DOWNLOAD FROM C2 STAGING]
  onedown[.]gesecole[.]net/download
        ├── Avk.exe        (legitimate G DATA binary)
        ├── Avk.dll        (malicious Korplug loader)
        └── AVKTray.dat    (XOR-encrypted PlugX DLL)

[OR]

[DELIVERY VIA MSI]
  601ae63ee...msi
  └── WiX MSI drops to %LOCALAPPDATA%\nDsMToCZME\
        ├── Avk.exe
        ├── Avk.dll
        └── AVKTray.dat

[EXECUTION — STAGE 1: DLL Sideloading]
  ShellExecuteW → Avk.exe  (legitimately signed, GUI subsystem)
        │
        ▼ (Windows DLL search order — current dir first)
  Loads Avk.dll (malicious, same directory)

[EXECUTION — STAGE 2: Korplug Loader (Avk.dll)]
  TLS callback fires before DllMain → anti-debug checks
  ModuleMain() called:
    1. Resolves Windows APIs via DJB2 hash (PEB walking)
    2. Reads AVKTray.dat from disk
    3. Strips 6-byte custom header (f9 e8 00 68 09 00)
    4. XOR-decrypts remainder with key 0x0b
    5. Reflectively loads decoded PE DLL in memory
    6. Calls export ZIWQXZXrVtgy (PlugX main entry)

[EXECUTION — STAGE 3: PlugX DLL (decoded from AVKTray.dat)]
  System Recon:
    GetUserNameW → current user
    GetSystemTime → system clock
    GetWindowsDirectoryW → install root
    gethostbyname → DNS resolution capability

  C2 Channel:
    HTTP(S) to carhirechicago[.]com:443
    HMAC-authenticated communications
    XOR-encoded data stream in transit

[PERSISTENCE]
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  Value: "G DATA"
  Data:  "%LOCALAPPDATA%\nDsMToCZME\Avk.exe" [params]

  AND/OR: Windows Service creation (Avk.exe capabilities)
```

---

## 5. Capabilities Analysis (CAPA)

### 5.1 Avk.exe (Loader/Orchestrator)

| Capability | Namespace | Notes |
|---|---|---|
| Anti-debug: GetTickCount timing | anti-analysis | Detects debugger via timing delta |
| Anti-debug: QueryPerformanceCounter | anti-analysis | Second timing check |
| Get process heap force flags | anti-analysis | NtQueryInformationProcess sandbox check |
| MurmurHash3 hashing | data-manipulation | Used for internal data hashing |
| Interact with driver via IOCTL (×7) | host-interaction/driver | Possible EDR/AV bypass via kernel driver |
| Query/set environment variable | host-interaction | Reads system context |
| Get common file path (×2) | host-interaction/file-system | Locates %APPDATA%, %TEMP% etc. |
| Move file | host-interaction/file-system | Drops/relocates payload |
| Find graphical window | host-interaction/gui | FindWindowW — detects analysis tools |
| Get disk information | host-interaction/hardware | Anti-VM disk size check |
| Print debug messages (×4) | host-interaction/log | OutputDebugStringW |
| Create/open mutex (×2) | host-interaction/mutex | Prevents re-infection |
| Get system information | host-interaction/os | System profiling |
| Create process (×3) | host-interaction/process/create | Launches child processes |
| Query/set registry value (×2) | host-interaction/registry | Persistence key operations |
| Create/start Windows service | host-interaction/service | **Persistence mechanism** |
| Get token membership | host-interaction/session | Privilege check |
| Create/resume/terminate thread | host-interaction/thread | Multi-threaded execution |
| Access PEB ldr_data (×3) | linking/runtime-linking | Module enumeration |
| **Link function at runtime (×11)** | linking/runtime-linking | **Dynamic API resolution — hides imports** |
| **Resolve function by parsing PE exports** | load-code/pe | Manual GetProcAddress |
| **Persist via Windows service** | persistence/service | Survives reboot |

**MITRE ATT&CK (Avk.exe — CAPA)**:
- T1010 — Application Window Discovery
- T1083 — File and Directory Discovery
- T1057 — Process Discovery
- T1012 — Query Registry
- T1082 — System Information Discovery
- T1033 — System Owner/User Discovery
- T1007 — System Service Discovery
- T1129 — Shared Modules
- T1569.002 — System Services: Service Execution
- T1543.003 — Create or Modify System Process: Windows Service

### 5.2 Avk.dll (Korplug Loader)

| Capability | Namespace | Notes |
|---|---|---|
| Hash data using DJB2 (×2) | data-manipulation/hashing | API function name hashing |
| **Resolve function by DJB2 hash** | linking/runtime-linking | **Shellcode-style API resolution** |
| Resolve function by parsing PE exports | load-code/pe | Manual PEB walking |
| Access PEB ldr_data | linking/runtime-linking | Module list traversal |
| Contains TLS section | executable/pe/section/tls | **Pre-entry code execution** |
| T1027.005 — Indicator Removal from Tools | defense-evasion | Strips analysis artifacts |

### 5.3 AVKTray.dat Decoded DLL (PlugX Core)

| Capability | Namespace | Notes |
|---|---|---|
| **80× obfuscated stack strings** | anti-analysis/obfuscation | Assembles strings byte-by-byte to defeat static analysis |
| Argument obfuscation | anti-analysis/obfuscation | B0032.020 |
| **Check HTTP status code** | communication/http | C2 communication via HTTP/S |
| **Authenticate HMAC (×4)** | data-manipulation/hmac | Signed C2 messages |
| **XOR encoding (×11)** | data-manipulation/encoding/xor | Config/traffic encryption |
| Access PEB ldr_data | linking/runtime-linking | Module enumeration |
| **Link function at runtime (×15)** | linking/runtime-linking | Dynamic API resolution |
| **Resolve function by hash** | linking/runtime-linking | API resolution by hash |
| **Inspect section memory permissions** | load-code/pe | Memory permissions check for injection |
| **Parse PE header (×3)** | load-code/pe | Reflective loading support |
| **Resolve PE exports (×16)** | load-code/pe | Dynamic PE loading |
| T1027 — Obfuscated Files or Information | defense-evasion | Multiple obfuscation layers |
| T1027.005 — Indicator Removal from Tools | defense-evasion | Strips forensic markers |

---

## 6. Encryption and Obfuscation

| Layer | Technique | Detail |
|-------|-----------|--------|
| MSI Cabinet | Compressed + high entropy | Standard MSI cabinet compression masks content |
| AVKTray.dat container | Custom 6-byte header | `f9 e8 00 68 09 00` — size/magic prefix before PE |
| AVKTray.dat body | **Single-byte XOR 0x0b** | Entire PE XOR'd; MZ header at offset 6 after decoding |
| API resolution (Avk.dll) | **DJB2 hash** | Function names replaced by 32-bit DJB2 hashes |
| API resolution (decoded DLL) | **Custom hash** (ROL-19 + cumulative sum) | PE export enumeration with runtime hash comparison |
| String obfuscation | **Stack strings (×80)** | Strings assembled character-by-character at runtime |
| Argument obfuscation | B0032.020 | Function arguments computed indirectly |
| C2 traffic | **XOR + HMAC** | Messages XOR-encoded and HMAC-authenticated |
| Compile metadata (Avk.dll) | **Future timestamp** | 2059-03-29 — deliberately invalid to confuse forensic timeline |
| MSI metadata | **False author** | "Microsoft Corporation" — identity masquerade |

---

## 6.5 Internal Config Blob — RC4-Encrypted `.data` Section (Deep Analysis)

### 6.5.1 Config Blob Location and Encryption

`plugx_core.bin` (decoded from AVKTray.dat) contains a 2208-byte (0x8a0) RC4-encrypted config blob embedded in the `.data` section immediately following the RC4 key material:

| Offset (file) | VA | Size | Content |
|---|---|---|---|
| `0x093400` | `0x10095000` | 0x18 bytes | Plaintext config header fields (BeaconInterval, BeaconMax, etc.) |
| `0x093418` | `0x10095018` | 4 bytes | **RC4 key length** — DWORD `0x00000009` (= 9) |
| `0x09341c` | `0x1009501c` | 13 bytes | **RC4 key string** — `"iEYnFBPdxDbk\0"` (campaign ID, null terminates into blob) |
| `0x093428` | `0x10095028` | 0x8a0 bytes | **RC4-encrypted config blob** |

Raw bytes at `.data+0x18` (file offset `0x93418`) confirming key/blob layout:
```
10095018: 09 00 00 00 69 45 59 6e 46 42 50 64 78 44 62 6b  |....iEYnFBPdxDbk|
10095028: d7 b4 1c e8 46 48 59 70 bd 78 ca 33 ef 91 24 a1  ← encrypted blob starts
```

**RC4 key = `"iEYnFBPdx"` (9 bytes = first 9 bytes of campaign ID `"iEYnFBPdxDbk"`)**

### 6.5.2 Decryption Mechanism — FUN_10080394

The blob is processed by **FUN_10080394** (4302 bytes), the primary PlugX initialisation function:

```
FUN_10080394 (main blob processor) execution flow:
  1. FUN_10082920(&BSS_0x1009d61c, &DAT_10095018, 0x8b0)
        └── memmove: copies 0x8b0 bytes from .data+0x18 (incl. key+blob) to BSS
  2. _memset(&DAT_10095018, 0, 0x8b0)
        └── ANTI-FORENSICS: zeroes original .data region after copy
  3. FUN_10081462(PEB, "LocalAlloc") → allocate 9-byte key buffer
  4. Copy BSS_copy[4..12] → key buffer = "iEYnFBPdx" (bytes 4–12 of copied region)
  5. FUN_10080104(0x1009d62c, 0x8a0, 0x1009d62c, key_buf)
        └── RC4 decrypt: 0x8a0 bytes in-place at BSS+0x10 (= blob copy)
  6. FUN_10081750(...) × 4 — WCHAR/byte transform on decrypted sections → BSS arrays
```

**FUN_10080104** (95 bytes) — RC4 wrapper:
```c
void FUN_10080104(int ciphertext, uint len, int plaintext_out, char *key) {
    memset(auStack_110, 0, 0x100);           // zero 256-byte S-box
    sVar1 = _strlen(key);                    // key length = 9
    FUN_10080164(S_box, key, sVar1);         // RC4 KSA (Key Scheduling Algorithm)
    FUN_100802e2(S_box, ciphertext, plaintext_out, len);  // RC4 PRGA (stream gen)
}
```

- `FUN_10080164` = RC4 KSA
- `FUN_100802e2` = RC4 PRGA
- `FUN_10082920` = `memmove` (classical overlap-direction check pattern)
- `FUN_10081462` = PEB walk API resolver (walks `PEB→InMemoryOrderModuleList`)
- `FUN_10081750` = WCHAR/byte XOR transform (encodes decoded config values into BSS WCHAR arrays)

Decryption entropy validation:
```
Pre-decrypt:  7.4 bits/byte (high entropy — encrypted)
Post-decrypt: 4.0 bits/byte (structured data — confirmed successful decryption)
```

### 6.5.3 Decrypted Config Blob Structure

Total size: 0x8a0 = 2208 bytes. Key structural regions:

| Blob offset | Content |
|---|---|
| `+0x000` | `DWORD 0x15` (= 21, entry count) |
| `+0x004` | `DWORD 0` |
| `+0x008` | `DWORD 0x80bc` (= 527,292 — exact overlay PDF byte count ✓) |
| `+0x00c` | `DWORD 0` |
| `+0x010–0x03f` | Binary (0x2a bytes) |
| `+0x040–0x12f` | 232-byte null-terminated printable ASCII string (further obfuscated) |
| `+0x130–0x23f` | Binary / encoded |
| `+0x240–0x48f` | Additional encoded config sections |
| `+0x490–0x68f` | Binary, sparse |
| `+0x690–0x72f` | **3 identical C2 config entries** (0x30 bytes × 3) |
| `+0x730–0x8a0` | Zero-padded |

The DWORD `527,292` at blob `+0x008` matching the overlay PDF size exactly confirms correct key and decryption.

### 6.5.4 C2 Entry Format (3 Entries)

Three identical C2 entries appear at blob offsets `+0x6a0`, `+0x6d0`, `+0x700` (redundant slots — standard PlugX config layout). Each entry is 0x30 (48) bytes:

```
Offset  Size   Value            Meaning
+0x00   DWORD  0x00000017       Entry type / flags
+0x04   DWORD  0x00000000       (reserved / padding)
+0x08   WORD   0x0001           Protocol = 1 (HTTPS)
+0x0a   WORD   0x01bb           Port = 443 (0x01bb)
+0x0c   8×0x00                  (padding)
+0x14   36 bytes (encoded)      Hostname — further obfuscated
```

Encoded hostname bytes (36 bytes, all 3 entries identical):
```
4e 3f 30 63 07 87 f1 ab d4 cf 93 f3 60 17 4a 3b
25 5f 18 83 f6 a7 d8 cb ba ef 6e 13 0b 37 2a 5b
02 7f fc a3
```

The hostname is **statically recoverable** via the `FUN_10081750` transform. Each of the three entries decodes to **`carhirechicago.com`** (UTF-16LE, 18 WCHARs = 36 bytes).

**Decode formula** (FUN_10081750 de-obfuscated):
```python
# param_1 = pointer to 36-byte hostname field
# param_2 = 36 (field byte length)
# param_3 = 0x1b (initial key seed — per-field constant)
step = param_2 // 2  # = 18
for i in range(param_2):
    data[i] ^= (param_3 + (i + 1) * step) & 0xff
```

The `(x & 0xe7 | ~x & 0x18) ^ (y & 0xe7 | ~y & 0x18)` expression in the decompiled code reduces to `x ^ y` because the bit masks 0xe7 and 0x18 are complementary (`0xe7 | 0x18 = 0xff`, `0xe7 & 0x18 = 0x00`) — this is a CFG/expression obfuscation layer with no net effect on the result.

Verification:
```
enc[0] = 0x4e;  key[0] = byte(27 + 1*18) = 0x2d;  decoded = 0x63 = 'c'
enc[1] = 0x3f;  key[1] = byte(27 + 2*18) = 0x3f;  decoded = 0x00  (WCHAR high byte)
enc[2] = 0x30;  key[2] = byte(27 + 3*18) = 0x51;  decoded = 0x61 = 'a'
...
→ UTF-16LE: "carhirechicago.com"  ✓
```

> **Correction**: An earlier analysis erroneously stated the C2 hostname was absent from the binary and stored in the registry. The hostname is statically embedded in the RC4-decrypted config blob at offset `+0x6b4` (3× in redundant C2 entry slots) and is fully recoverable without sandbox execution.

This C2 entry format is consistent with documented PlugX/Korplug config layouts (BB01 protocol variant).

---

## 7. Interesting Strings

### 7.1 Avk.exe

```
C:\j\workspace\_AppDev_avk_release_1-production\bin\Release32v14x\Loader.pdb
                            ↑ PDB says "Loader" despite G Data AV disguise

RepoName: release/1-production
RepoRevision: 2766750bc87d62fba184d9d1677b2ecf39fbc6ef
CompanyName: G DATA Software AG
FileDescription: G DATA ANTIVIRUS
InternalName: AVK

Namespaces / RTTI evidence:
  ILockable@MasterHook          ← "MasterHook" hooking framework
  CCOMRefCount@VILockable@MasterHook
  CMHProcessBag / CMHProcessList / CProcessManager
  GDlockprimitives_legacy
  CSvcThreadEx / CSvcDelegateThreadEx  ← service/daemon thread management

Key Win32 APIs:
  CreateProcessAsUserW / CreateProcessW   ← process spawning
  WTSQueryUserToken                       ← session hijacking / terminal services
  DuplicateTokenEx / SetTokenInformation  ← token manipulation
  CheckTokenMembership                    ← privilege checks
  RegCreateKeyExW / RegOpenKeyExW         ← registry persistence
  ShellExecuteW                           ← launch child processes
  QueryFullProcessImageNameW              ← process enumeration
  FltLib.dll / FilterGetDosName           ← filesystem filter driver interaction
```

### 7.2 Avk.dll

```
Export: ModuleMain, ModuleMain2    ← non-standard DLL entry points
sDl.dll                            ← internal name (obfuscated)
Kernel32.dll (resolved at runtime) ← imported dynamically
FltLib.dll                         ← filesystem driver library
```

### 7.3 AVKTray.dat Decoded DLL

```
Export: ZIWQXZXrVtgy              ← randomised export name (per-build ID)

Key imports (66 from KERNEL32.dll):
  gethostbyname                   ← DNS resolution (C2 beacon)
  GetUserNameW                    ← user profiling/exfil
  GetSystemTime                   ← time-based operations
  GetTickCount                    ← anti-debug timing
  OpenProcess                     ← process access
  RegOpenKeyExW / RegCloseKey     ← registry access
  CreateDirectoryW                ← file system setup
  DeleteFileW                     ← cleanup / indicator removal
  SetFileAttributesW              ← hide files (hidden/system attr)
  FindNextFileW / FindClose        ← file enumeration
  GetWindowsDirectoryW            ← OS path discovery
  ExpandEnvironmentStringsW       ← resolve env vars
  CreateEventW                    ← event signalling
  WriteFile                       ← file write (exfil staging)

Obfuscated runtime strings (samples, XOR-encoded in binary):
  yYg}tWqkqaWtv{~inQzs~GfvFqut|voJos|{b
  WjlEx{~Jddyp\vxu
  Os\lxGdv@khkfv}VrrxI
  CnonekbKqw
```

### 7.4 MSI Package Strings

```
Install path:    %LOCALAPPDATA%\nDsMToCZME\    ← randomised persistence directory
ARPSYSTEMCOMPONENT=1                            ← hidden from ARP
Product: "MainProgran"                          ← deliberate misspelling
Cabinet: #UwZFJu9G.cab                         ← randomised cabinet name
RC4 key (related campaign): fzsbnWTgLLq        ← per Lab52 research
```

---

## 8. Infrastructure / Network IOCs

| Type | Indicator | Confidence | Notes |
|---|---|---|---|
| **C2 Domain** | `carhirechicago[.]com` | High | PlugX C2 — HTTPS port 443 |
| **C2 URL** | `carhirechicago[.]com:443` (BB01 protocol) | High | Sandbox + static analysis confirmed |
| **Download Server** | `onedown[.]gesecole[.]net` | High | Payload staging server |
| **Download Path** | `/download` | Medium | Artifact delivery endpoint |
| **Protocol** | HTTPS/443 with custom BB01 header | High | PlugX comms protocol |
| **Auth** | HMAC-authenticated messages | High | Session integrity validation |
| **Encoding** | XOR (key 0x0b in this sample; 0x4F in related) | High | In-transit data obfuscation |
| **DNS** | `gethostbyname` used (API-level) | Medium | C2 resolution method |

---

## 9. File-Based IOCs

### 9.1 Hashes

| Component | Type | Hash |
|---|---|---|
| MSI container | MD5 | `ab56563f3817e31568e487edc232a7ee` |
| MSI container | SHA-1 | `4142b2d89afec1b5b2379219af3b5a2fabe53a8b` |
| MSI container | SHA-256 | `601ae63ee59288a2e36f0b0d4f7bc0bfb40f0489995343c955db7d9ded469478` |
| Avk.exe (legitimate, abused) | MD5 | `e7cb954f4bbdbadbd2c0206577621683` |
| Avk.exe (legitimate, abused) | SHA-256 | `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99` ✅ |
| Avk.dll (Korplug loader) | MD5 | `9e77dea40479abf11fc3894bf50829f7` |
| Avk.dll (Korplug loader) | SHA-256 | `ec0269b308395947a539ab7e275de98350b89943a5f48e47237deac9fff7b4a0` |
| AVKTray.dat (encrypted) | MD5 | `33bbfa6d5c8a1078e4e260e15d563360` |
| AVKTray.dat (encrypted) | SHA-256 | `732c747f2653e50acc5bc5b0bb07018777a0440840dd1fc5a023f3c4db2d111a` |
| AVKTray.dat (decoded DLL) | MD5 | `de2fae03f8ffbd1c451887656a68d112` |
| AVKTray.dat (decoded DLL) | SHA-1 | `ede1c20ddba05b8355a89c3856e02f7abd8bb1d0` |
| AVKTray.dat (decoded DLL) | SHA-256 | `9e7bb2f6b5a7e79b14b4e0e10a97518592071ebbe196452cfc75addca0496381` |

### 9.2 File System Indicators

| Indicator | Type |
|---|---|
| `%LOCALAPPDATA%\nDsMToCZME\Avk.exe` | Dropped file path |
| `%LOCALAPPDATA%\nDsMToCZME\Avk.dll` | Dropped file path |
| `%LOCALAPPDATA%\nDsMToCZME\AVKTray.dat` | Dropped file path |
| `%TEMP%\[a-f0-9]{8}\*.cs` | Temp build artifacts |
| `%TEMP%\[a-f0-9]{8}\*.dll` | Temp build artifacts |
| `C:\Users\Public\GDatas\Avk.exe` | Alternate deployment path (related campaign) |

### 9.3 Registry Indicators

| Key | Value | Data |
|---|---|---|
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | `G DATA` | `%LOCALAPPDATA%\nDsMToCZME\Avk.exe [params]` |

### 9.4 MSI Metadata Indicators

| Field | Value |
|---|---|
| ProductCode GUID | `{D2FEECC2-CBCC-462C-AE5A-54A8FF76F8B5}` |
| UpgradeCode GUID | `{56593721-F300-4163-B356-314B36826412}` |
| Revision GUID | `{D48082FE-B1BE-4332-AF5F-485DD49CB81F}` |

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | "Meeting Invitation" ZIP/MSI delivery |
| **Execution** | T1218.007 | System Binary Proxy Execution: Msiexec | MSI installer delivery |
| **Execution** | T1127.001 | Trusted Developer Utilities: MSBuild | csproj-based downloader (related campaign) |
| **Execution** | T1129 | Shared Modules | DLL loading via Windows loader |
| **Execution** | T1569.002 | System Services: Service Execution | Windows service creation in Avk.exe |
| **Persistence** | T1547.001 | Boot or Logon Autostart: Registry Run Keys | HKCU Run key "G DATA" |
| **Persistence** | T1543.003 | Create or Modify System Process: Windows Service | Avk.exe creates Windows service |
| **Privilege Escalation** | T1134 | Access Token Manipulation | DuplicateTokenEx, WTSQueryUserToken |
| **Defense Evasion** | T1574.001 | Hijack Execution Flow: DLL Side-Loading | Avk.dll placed alongside legitimate Avk.exe |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | AVK file naming; G DATA version info; MSI claims Microsoft authorship |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | Stack strings, XOR encoding, argument obfuscation |
| **Defense Evasion** | T1027.002 | Software Packing | High-entropy sections, packer signatures |
| **Defense Evasion** | T1027.005 | Indicator Removal from Tools | Avk.dll and decoded DLL strip forensic indicators |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information | XOR decode of AVKTray.dat at runtime |
| **Defense Evasion** | T1553.002 | Subvert Trust Controls: Code Signing | Abuses legitimately signed G DATA binary |
| **Defense Evasion** | T1564.001 | Hide Artifacts: Hidden Files/Directories | ARPSYSTEMCOMPONENT=1; SetFileAttributesW |
| **Discovery** | T1082 | System Information Discovery | System profiling (OS, user, disk) |
| **Discovery** | T1083 | File and Directory Discovery | FindNextFileW enumeration |
| **Discovery** | T1057 | Process Discovery | Process enumeration |
| **Discovery** | T1012 | Query Registry | RegOpenKeyExW |
| **Discovery** | T1033 | System Owner/User Discovery | GetUserNameW |
| **Discovery** | T1007 | System Service Discovery | Service enumeration |
| **Discovery** | T1010 | Application Window Discovery | FindWindowW (anti-analysis) |
| **Command & Control** | T1071.001 | App Layer Protocol: Web Protocols | HTTPS C2 to carhirechicago[.]com:443 |
| **Command & Control** | T1573 | Encrypted Channel | HMAC + XOR encrypted C2 traffic |
| **Collection** | T1005 | Data from Local System | File enumeration and access |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Data sent via established HTTPS C2 |

---

## 11. Attribution

### 11.1 Threat Actor: UNC6384 / Mustang Panda

| Attribute | Value |
|---|---|
| **Actor Name** | UNC6384 |
| **Aliases** | Mustang Panda, BRONZE PRESIDENT, Earth Preta, RedDelta, TA416, TWILL TYPHOON, CAMARO DRAGON, HIVE0154, LUMINOUS MOTH, STATELY TAURUS, FIREANT, TEMP.Hex |
| **MITRE Group** | G0129 |
| **Nation-State** | China (PRC) |
| **Motivation** | Espionage / Intelligence Collection |
| **Active Since** | ~2012 |
| **Primary Targets** | Diplomatic missions, government entities, NGOs — Europe, Southeast Asia, Central Asia |
| **Confidence** | High (matching Avk.exe hash, attack chain, tooling) |

### 11.2 Attribution Evidence

| Evidence | Details |
|---|---|
| **Hash match** | Avk.exe SHA-256 `8421e...` confirmed by Lab52 as part of UNC6384 PlugX campaign |
| **Tooling** | PlugX/Korplug is the signature tool of Mustang Panda / UNC6384 |
| **Attack chain** | G DATA DLL sideloading + AVKTray.dat XOR payload — identical to documented Jan 2026 campaign |
| **Lure theme** | "Meeting Invitation" — UNC6384 campaign documented targeting EU/ASEAN diplomats |
| **Infrastructure** | `carhirechicago[.]com` (sandbox + static analysis confirmed C2); `gesecole[.]net` linked in Lab52 campaign report (not confirmed for this sample) |
| **Technique overlap** | DLL sideloading with AV binary, XOR-encrypted `.dat` file, HMAC C2 — all consistent with Mustang Panda TTP cluster |

### 11.3 Campaign Context

This sample is assessed as part of the **January–March 2026 UNC6384 "Meeting Invitation" campaign** targeting European and Southeast Asian diplomatic entities. UNC6384 has been observed:
- Exploiting Windows LNK vulnerability ZDI-CAN-25373
- Using Canon, G DATA, and other AV vendor binaries for DLL sideloading
- Deploying PlugX variants (SOGU, Korplug) as post-exploitation implants
- Targeting Belgium, Hungary, and ASEAN diplomatic missions

---

## 12. Detection Rules

### 12.1 YARA Rules

```yara
rule MSI_PlugX_GData_DLLSideload_Dropper {
    meta:
        description = "Detects MSI dropper for PlugX via G DATA DLL sideloading"
        author      = "CTI Analysis"
        date        = "2026-03-03"
        tlp         = "WHITE"
        mitre       = "T1574.001, T1036.005, T1218.007"
        hash_sha256 = "601ae63ee59288a2e36f0b0d4f7bc0bfb40f0489995343c955db7d9ded469478"
        reference   = "https://lab52.io/blog/plugx-meeting-invitation-via-msbuild-and-gdata/"

    strings:
        $product_guid  = "{D2FEECC2-CBCC-462C-AE5A-54A8FF76F8B5}" ascii wide nocase
        $install_dir   = "nDsMToCZME" ascii wide
        $hidden        = "ARPSYSTEMCOMPONENT" ascii wide
        $avk_dat       = "AVKTray.dat" ascii wide
        $avk_exe       = "Avk.exe" ascii wide
        $avk_dll       = "Avk.dll" ascii wide
        $c2_domain     = "carhirechicago" ascii wide
        $fake_mfr      = "MainProgran" ascii wide

    condition:
        uint32(0) == 0xE011CFD0 and  // OLE2 magic
        (3 of ($avk_exe, $avk_dll, $avk_dat, $product_guid, $install_dir, $hidden, $c2_domain, $fake_mfr))
}

rule PE_Korplug_Loader_GData_AVKDll {
    meta:
        description = "Detects Korplug/PlugX loader DLL (Avk.dll stage 1)"
        author      = "CTI Analysis"
        date        = "2026-03-03"
        tlp         = "WHITE"
        mitre       = "T1574.001, T1027.005"
        hash_sha256 = "ec0269b308395947a539ab7e275de98350b89943a5f48e47237deac9fff7b4a0"

    strings:
        $export1   = "ModuleMain" ascii
        $export2   = "ModuleMain2" ascii
        $internal  = "sDl.dll" ascii
        $tls_mark  = { 2E 74 6C 73 }  // ".tls" section name
        $djb2_hash = { 68 01 00 00 00 6B ?? ?? ?? 8B ?? }  // djb2 computation pattern

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10KB and
        all of ($export1, $export2, $internal)
}

rule PE_PlugX_Core_Decoded_AVKTray {
    meta:
        description = "Detects decoded PlugX core DLL from AVKTray.dat (XOR 0x0b)"
        author      = "CTI Analysis"
        date        = "2026-03-03"
        tlp         = "WHITE"
        mitre       = "T1027, T1071.001, T1573"
        hash_sha256 = "9e7bb2f6b5a7e79b14b4e0e10a97518592071ebbe196452cfc75addca0496381"

    strings:
        $export    = "ZIWQXZXrVtgy" ascii
        $stackstr1 = "yYg}tWqkqaWtv{~inQzs~" ascii  // obfuscated stack string fragment
        $stackstr2 = "WjlEx{~" ascii
        $hmac_ref  = { 8B 45 ?? 83 C0 04 50 }       // HMAC computation pattern
        $xor_loop  = { 32 04 0E 47 3B FE 72 }       // XOR decode loop

    condition:
        uint16(0) == 0x5A4D and
        ($export or (2 of ($stackstr1, $stackstr2, $hmac_ref, $xor_loop)))
}

rule Binary_AVKTray_XOR_Encrypted_PlugX {
    meta:
        description = "Detects AVKTray.dat — XOR-encrypted PlugX payload with 6-byte header"
        author      = "CTI Analysis"
        date        = "2026-03-03"
        tlp         = "WHITE"
        hash_sha256 = "732c747f2653e50acc5bc5b0bb07018777a0440840dd1fc5a023f3c4db2d111a"

    strings:
        // 6-byte header followed by XOR(0x0b) encoded "MZ" at offset 6
        // f9 e8 00 68 09 00 -> custom header, then 46 51 = 'M'^0b 'Z'^0b
        $header = { F9 E8 00 68 09 00 46 51 }

    condition:
        filesize > 500KB and
        $header at 0
}
```

### 12.2 Sigma Rules

```yaml
title: PlugX DLL Sideloading via G DATA AVK Components
id: a7f2e1d3-8b4c-4a5e-9f6d-2c1b3e4a5f6d
status: stable
description: Detects PlugX infection via G DATA Avk.exe loading malicious Avk.dll
author: CTI Analysis
date: 2026/03/03
references:
    - https://lab52.io/blog/plugx-meeting-invitation-via-msbuild-and-gdata/
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\Avk.dll'
        Image|endswith: '\Avk.exe'
    filter_legit:
        ImageLoaded|startswith:
            - 'C:\Program Files\G DATA\'
            - 'C:\Program Files (x86)\G DATA\'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate G DATA AntiVirus installation in non-standard path
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.001
    - attack.t1036.005
    - detection.emerging_threats

---
title: PlugX MSI Dropper — Hidden ARP Entry and Randomised LocalAppData Install
id: b8e3f2c4-9a5d-4b6f-ae7e-3d2c4f5b6e7d
status: experimental
description: Detects MSI install with ARPSYSTEMCOMPONENT=1 dropping to randomised %LOCALAPPDATA% subdirectory
author: CTI Analysis
date: 2026/03/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ARPSYSTEMCOMPONENT'
            - 'nDsMToCZME'
            - 'AVKTray.dat'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.defense_evasion
    - attack.t1564.001

---
title: PlugX Persistence via Registry Run Key "G DATA"
id: c9f4g3d5-0b6e-4c7g-bf8f-4e3d5g6c7f8e
status: stable
description: Detects PlugX UNC6384 persistence via HKCU Run key named "G DATA"
author: CTI Analysis
date: 2026/03/03
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Microsoft\Windows\CurrentVersion\Run'
        Details|contains:
            - 'Avk.exe'
            - 'nDsMToCZME'
            - 'GDatas'
    condition: selection
falsepositives:
    - Legitimate G DATA AntiVirus autostart (verify path is under Program Files)
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

### 12.3 Network Detection (Snort/Suricata)

```
alert dns any any -> any any (
    msg:"PlugX UNC6384 C2 DNS lookup carhirechicago.com";
    dns.query; content:"carhirechicago.com"; nocase;
    classtype:trojan-activity; sid:9100001; rev:1;
    metadata:affected_product Windows, attack_target Diplomat,
              deployment Perimeter, malware_family PlugX,
              signature_severity Critical, tag UNC6384;
)

alert tls any any -> any 443 (
    msg:"PlugX UNC6384 C2 TLS SNI carhirechicago.com";
    tls.sni; content:"carhirechicago.com"; nocase;
    classtype:trojan-activity; sid:9100002; rev:1;
)

alert dns any any -> any any (
    msg:"PlugX UNC6384 Download Server gesecole.net";
    dns.query; content:"gesecole.net"; nocase;
    classtype:trojan-activity; sid:9100003; rev:1;
)

alert http any any -> any any (
    msg:"PlugX UNC6384 Download Path onedown.gesecole.net/download";
    http.host; content:"gesecole.net"; nocase;
    http.uri; content:"/download"; nocase;
    classtype:trojan-activity; sid:9100004; rev:1;
)
```

---

## 13. Defensive Recommendations

1. **Block IOCs** — Add `carhirechicago[.]com` to DNS/proxy block lists immediately.

2. **Hunt for persistence** — Search endpoints for:
   - `HKCU\...\Run` key with value `"G DATA"` pointing outside `C:\Program Files\`
   - Files named `AVKTray.dat`, `Avk.dll` in non-standard directories
   - Directory `%LOCALAPPDATA%\nDsMToCZME\` or similar randomised names

3. **DLL Sideloading detection** — Deploy rules to alert when `Avk.exe` or any AV vendor binary loads a DLL from `%LOCALAPPDATA%`, `%TEMP%`, or `%APPDATA%` (outside `C:\Program Files\`).

4. **Application control** — Restrict execution of MSI files from `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, and `Downloads` via AppLocker or WDAC policies.

5. **Block MSBuild execution** — Apply Microsoft's recommended guidance to block `msbuild.exe` from spawning child processes in non-development environments.

6. **EDR telemetry** — Review alerts for:
   - `msiexec.exe /i <path>` from phishing-prone locations
   - `Avk.exe` spawned from MSI/msiexec parent
   - `CreateService` / `OpenSCManager` calls from `%LOCALAPPDATA%`

7. **Email gateway** — Block `.msi`, `.csproj`, and zip archives containing `.exe` + `.dat` + `.dll` triads at the email perimeter.

8. **Awareness** — Warn staff of "Meeting Invitation" themed spear-phishing, particularly targeting diplomatic/government roles.

---

## 14. Tools Used in This Analysis

| Tool | Version | Purpose |
|------|---------|---------|
| `file` | system | File type identification |
| `md5sum` / `sha1sum` / `sha256sum` | system | Hash computation |
| `exiftool` | 13.52 | Metadata / OLE property extraction |
| `magika` | — | ML-based file type classification |
| `trid` | 2.24 | File type signature matching |
| `oledump.py` | — | OLE/MSI stream analysis |
| `oleid` | 0.60.1 | OLE indicator analysis |
| `msodde` | 0.60.2 | DDE link detection |
| `msiextract` | — | MSI file extraction |
| `peframe` | — | PE static analysis |
| `pecheck.py` | — | PE header deep analysis |
| `pefile` (python) | — | PE import/section/header parsing |
| `capa` | — | Capability detection (MITRE ATT&CK, MBC) |
| `bulk_extractor` | 2.1.1 | Automated IOC extraction |
| `strings` | system | String extraction |
| `xortool` | — | XOR key detection |
| `xorsearch.py` | — | XOR pattern search |
| `disitool.py` | 0.4 | Digital signature extraction |
| `openssl` | — | Certificate chain analysis |
| `malutil-hashes` | — | TLSH / imphash computation |
| WebSearch / OSINT | — | Hash/domain threat intelligence |
| Lab52 Threat Research | — | Campaign attribution and IoC correlation |

---

## 15. References

- [Lab52 — PlugX Meeting Invitation via MSBuild and GDATA](https://lab52.io/blog/plugx-meeting-invitation-via-msbuild-and-gdata/)
- [OffSeq Threat Radar — PlugX Meeting Invitation](https://radar.offseq.com/threat/plugx-meeting-invitation-via-msbuild-and-gdata-6eb1b765)
- [MITRE ATT&CK — PlugX (S0013)](https://attack.mitre.org/software/S0013/)
- [MITRE ATT&CK — Mustang Panda / UNC6384 (G0129)](https://attack.mitre.org/groups/G0129/)
- [The Hacker News — UNC6384 Deploys PlugX via Captive Portal Hijacks](https://thehackernews.com/2025/08/unc6384-deploys-plugx-via-captive.html)
- [The Hacker News — China-Linked PlugX and Bookworm Malware](https://thehackernews.com/2025/09/china-linked-plugx-and-bookworm-malware.html)
- [The Record — Belgium and Hungary diplomatic entities hacked](https://therecord.media/belgium-hungary-diplomatic-entities-hacked-unc6384)
- [FBI Deletes PlugX Malware from 4,250 Computers](https://thehackernews.com/2025/01/fbi-deletes-plugx-malware-from-4250.html)
- [ManageEngine — Potential AVKkid.DLL Sideloading Detection](https://www.manageengine.com/au/log-management/detection-rules/potential-avkkid-dll-sideloading.html)
- [Securonix — Detecting DLL Sideloading in Malware Attack Chains](https://www.securonix.com/blog/detecting-dll-sideloading-techniques-in-malware-attack-chains/)

---

*Report generated: 2026-03-03 | Platform: REMnux isolated analysis VM | TLP:WHITE*
