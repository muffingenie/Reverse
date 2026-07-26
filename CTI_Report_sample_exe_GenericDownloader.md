# Malware Analysis Report — Generic HTTP Downloader ("winsvcn.exe" / sample.exe)

**TLP:AMBER** — internal / cleared-partner distribution only (contains active C2 infrastructure).

## Contents
- [Executive Summary](#executive-summary)
- [Sample Snapshot](#sample-snapshot)
- [Malware Family Identification](#malware-family-identification)
- [Component Inventory](#component-inventory)
- [Runtime Requirements](#runtime-requirements)
- [Sources](#sources)
- [Capabilities](#capabilities)
- [Indicators of Compromise](#indicators-of-compromise)
- [Analysis Details](#analysis-details)
- [What We Don't Know](#what-we-dont-know)
- [Detection Engineering](#detection-engineering)
- [About this Report](#about-this-report)
- [Appendix: Analysis Environment](#appendix-analysis-environment)

## Executive Summary

`sample.exe` is a small (11,776-byte) native Win32 GUI executable, compiled with Microsoft Visual C++ 9.0 (VS2008), statically linked against WinINet, SHLWAPI, and SHELL32. It is a first-stage **downloader/loader**: on first execution it copies itself to `%USERPROFILE%\winsvcn.exe`, strips the Mark-of-the-Web (Zone.Identifier ADS) from the copy, installs persistence via the `HKCU\...\CurrentVersion\Run` key under the value name **"Windows Service Manager"**, launches the persistent copy, and exits. On subsequent (persistent) runs it enforces single-instance execution via a named mutex, performs an HTTP "check-in"/version probe against `hxxp://178.16.54.109/prel[.]php`, then downloads a second-stage payload from `hxxp://178.16.54.109/vload[.]exe` via `URLDownloadToFileW` to a randomly named file in `%TEMP%`, strips the MOTW mark from the downloaded file, and executes it via `ShellExecuteW`. The C2 IP sits on **OMEGATECH (AS202412)**, a Seychelles-registered bulletproof-hosting network independently documented (Breakglass Intelligence, gbhackers, cybersecuritynews, cyberpress) as currently hosting dozens of C2 servers for at least 16 distinct commodity malware families (Remcos, AsyncRAT, Amadey, XWorm, Rhadamanthys, Cobalt Strike, among others). No sample-intrinsic evidence (YARA family signature, code-similarity, or unique string) ties this specific binary to a named family — it should be treated as an unattributed, generic commodity downloader whose sole confirmed lineage is its hosting provider.

## Sample Snapshot

| | |
|---|---|
| **Malware Family** | Unattributed generic downloader/loader (no confirmed family — see [Malware Family Identification](#malware-family-identification)) |
| **Key Capabilities** | HTTP-based C2 check-in and payload download (WinInet/URLDownloadToFileW), self-copy + Registry Run-key persistence, Mark-of-the-Web (Zone.Identifier) stripping, mutex-based single-instance enforcement |
| **Target Platform** | Windows (x86/32-bit), native PE32 GUI subsystem |
| **Primary Artifact** | sample.exe — SHA-256 `4c5529e4e93f8504affd39e5deea46a1ea4410600e39a9c66d18d9dc2cddb204` |
| **Infection Vector** | Unknown / not provided with the sample (delivery mechanism not observed in this analysis) |

## Malware Family Identification

| Family | Basis | Confidence |
|---|---|---|
| *(none confirmed)* | yara-forge (45+ source ruleset, incl. Malpedia/ReversingLabs) produced **no family match**; capa/behavioral profile is generic (downloader-category MAEC tag only); no code-reuse or imphash correlation performed against a named family | N/A |
| Hosting-network association: OMEGATECH bulletproof hosting (AS202412) | RDAP registrant "Omegatech LTD" (Seychelles) for 178.16.54.109; independently corroborated by multiple OSINT reports (Breakglass Intelligence, gbhackers, cybersecuritynews) describing AS202412 as a BPH network hosting 67 C2 servers across 16 malware families | High (for the hosting-provider association only — this is infrastructure context, **not** malware-family attribution) |

Per ICD-203 estimative language: confidence in *family* identification is **low/none** — the filename ("winsvcn.exe", "Windows Service Manager") is attacker-supplied metadata and is not treated as evidence. Confidence in the *hosting-infrastructure* characterization (shared BPH network, high blast-radius, multi-family) is **high**, based on independent, non-sample-derived reporting.

## Component Inventory

| Role | File Name | File Type | Notes |
|---|---|---|---|
| Stage-1 downloader / persistence installer | sample.exe | PE32 executable (GUI), Intel 80386, 5 sections | MD5 `c2d1ac4a8b2cb770fc1f594c3b050a8a`; installs itself as `winsvcn.exe` |
| Stage-2 payload | *(not obtained)* | unknown | Fetched at runtime from `hxxp://178.16.54.109/vload.exe`; not retrieved during this analysis (see [What We Don't Know](#what-we-dont-know)) |

Flow: `sample.exe` (first run) → copies self to `%USERPROFILE%\winsvcn.exe`, sets Run-key persistence, launches copy, exits → `winsvcn.exe` (persistent copy, subsequent runs/reboots) → HTTP check-in to `prel.php` → downloads and executes `vload.exe` payload from `%TEMP%\<random><random>.exe`.

## Runtime Requirements

- **Architecture:** 32-bit x86, PE32, `IMAGE_FILE_MACHINE_I386`, Windows GUI subsystem, not statically linked to the CRT (dynamically imports MSVCR90.dll — requires the VC++ 2008 (9.0.21022.8) redistributable, declared via embedded SxS manifest `Microsoft.VC90.CRT`).
- **Imported DLLs:** KERNEL32.dll, USER32.dll, ADVAPI32.dll, SHELL32.dll, SHLWAPI.dll, WININET.dll, urlmon.dll, MSVCR90.dll.
- **Network:** outbound HTTP (port 80) to 178.16.54.109 required for the download/execute chain to function; no TLS.
- **No packing/obfuscation observed** — compiled with Microsoft Linker 9.00.30729 / VC++ 15.00.30729 (VS2008), not packed (UPX unpack and AutoIt-unpack attempts both failed/were not applicable — those triage flags were false leads from generic heuristics, not actual packing).

## Sources

- Sample supplied directly for analysis (`/home/remnux/files/samples/sample.exe`); no prior chain-of-custody or delivery context provided.
- Analysis performed entirely via local static analysis and disassembly on a REMnux instance (no sandbox detonation was performed; no vendor/sandbox sample lookups against the SHA-256 were run in this pass — see [What We Don't Know](#what-we-dont-know)).
- OSINT: RIPE RDAP, ipinfo.io, Shodan InternetDB (all passive/non-disclosing), and web search for the hosting ASN.

## Capabilities

Primary MBC/ATT&CK objectives: **Command and Control** (HTTP-based check-in and payload retrieval), **Persistence** (Registry Run key), **Defense Evasion** (Mark-of-the-Web bypass), **Discovery** (file/directory existence checks), and **Anti-Behavioral-Analysis** (timing check via `GetTickCount`, though see caveat below).

| MBC Behavior | Procedure Observed | Notes |
|---|---|---|
| Communication::HTTP Communication (C0002, incl. Create/Download/Open/Get Response) | `InternetOpenA/W`, `InternetOpenUrlA/W`, `HttpQueryInfoA`, `InternetReadFile`, `URLDownloadToFileW` all imported and reachable from `main` via `fcn.00401120` (check-in) and `fcn.004011c0` (download) | Behavior-confirmed statically: APIs imported AND cross-referenced from executable code reachable from the entry point (capa evidence_types = behavior, not artifact-only) |
| Persistence::Registry Run Keys / Startup Folder (F0012) | `RegOpenKeyExW`/`RegSetValueExW` on `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` with value name "Windows Service Manager" pointing at `%USERPROFILE%\winsvcn.exe` | Confirmed reachable code path (T1547.001) |
| Defense Evasion::Mark-of-the-Web Bypass (T1553.005) | `DeleteFileW` on `<path>:Zone.Identifier` alternate data stream, applied both to the self-copy and to the downloaded payload | Confirmed via code xref, executed unconditionally in both install and download paths |
| File System::Copy/Delete/Set Attributes/Write File | `CopyFileW` (self-copy), `SetFileAttributesW` (attribute 3 = READONLY\|HIDDEN on the copy), `CreateFileW`/`WriteFile` for the downloaded payload | Confirmed |
| Process::Create Mutex / Check Mutex / Create Process | `CreateMutexA("5886844846")`, checked via `GetLastError()==ERROR_ALREADY_EXISTS(0xB7)`; `ShellExecuteW(..., "open", ...)` to launch both the persistent copy and the downloaded payload | Single-instance guard; confirmed |
| Anti-Behavioral-Analysis::Timing/Delay Check (B0001.032) | `GetTickCount` used only to seed `srand()` for randomizing the downloaded file's temp name — **not** used as a debugger/timing-detection check | Artifact-only misclassification by capa's generic rule; verified by code reading this is **not** anti-analysis behavior — flagging as a corrected false lead |
| Discovery::File and Directory Discovery / System Information Discovery | `PathFileExistsW` on a `%TEMP%\525352353.jpg` marker file (first-run flag), `GetModuleFileNameW`/`PathFindFileNameW` for self-path resolution | Confirmed |

`IsDebuggerPresent` and `SetUnhandledExceptionFilter`/`UnhandledExceptionFilter` are imported but were not observed called from any analyzed function — these are standard MSVCR90 CRT startup/exception-handling boilerplate for VC++ 2008 binaries, not evidence of deliberate anti-debugging. Treat as artifact-only/CRT noise, not a capability.

## Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Hash Values | MD5 `c2d1ac4a8b2cb770fc1f594c3b050a8a` / SHA-1 `5dbb0bab48b31e4e9911d1e70f727049ff81129f` / SHA-256 `4c5529e4e93f8504affd39e5deea46a1ea4410600e39a9c66d18d9dc2cddb204` / imphash `38ca2cef077b08d131c2be3bfd70789c` / ssdeep `192:2pd4GvyoejTWghMfhjff7JJfxMLkWScZqYa/DT:2pd4sv6vsTxMQWSc9` | Stage-1 downloader (sample.exe / self-renamed winsvcn.exe). Not found in Team Cymru MHR (hash unknown to that feed — inconclusive, not exculpatory). |
| IP Addresses | 178[.]16.54.109 | C2/download host — RIPE-registered to Omegatech LTD (AS202412 "OMEGATECH"), Seychelles; geolocated Amsterdam, NL; documented bulletproof-hosting network |
| Domain Names | *(none — C2 accessed by bare IP over HTTP)* | |
| Network Artifacts | `hxxp://178[.]16.54.109/prel.php` (check-in/version probe), `hxxp://178[.]16.54.109/vload.exe` (payload download); hardcoded User-Agent strings mimicking Chrome 93.0.4577.82 / 104.0.0.0 / 110.0.0.0 on Windows 10 x64 | All three URLs/UAs are directly cross-referenced from executable code (confirmed operational use, not vestigial strings) |
| Host Artifacts | Mutex `5886844846`; Registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\"Windows Service Manager"`; dropped file `%USERPROFILE%\winsvcn.exe`; marker file `%TEMP%\525352353.jpg` (zero-byte first-run flag, not an actual image); downloaded payload path pattern `%TEMP%\<2 random 4-5 digit numbers>.exe` | Mutex name and Run-key value name are moderately distinctive pivot candidates; the Run-key path itself (`CurrentVersion\Run`) is a common/weak pivot on its own |

*(Full IOC set including duplicated hash artifacts extracted from embedded padding is in the raw tool output; a large number of MD5/SHA1/SHA256/SHA512 values and email addresses (e.g. `joakim@intezer.com`, `mehunhoff@google.com`, references to `intezer.com`/`mandiant.com`) were extracted by automated string scraping but are almost certainly incidental — see [What We Don't Know](#what-we-dont-know) for the unresolved padding/overlay question.)*

## Analysis Details

### Automated Analysis

REMnux MCP `analyze_file` (standard depth, 17 tools) was run first: peframe, diec, capa, pestr, portex, yara-forge, pecheck, pescan, signsrch, autoit-ripper, upx-decompress, manalyze, 1768.py (Cobalt Strike config parser — no match, garbage parse on non-CS binary), csce, redress (no Go), ssdeep, exiftool. `diec` and `autoit-ripper`/`upx-decompress` triage flags for "AutoIt compiled" / "UPX packed" in the initial triage summary were both **false leads**: `autoit-ripper` and `upx -d` both failed outright (no AutoIt resource chunk found, no valid UPX header), and `diec` unambiguously fingerprints the linker/compiler as Microsoft Linker 9.00.30729 / VC++ 15.00.30729 (VS2008) with no packer signature. The binary is not packed.

### Static Properties Analysis

| Property | Significance |
|---|---|
| Compiler/Linker: Microsoft Visual C++ 9.0 / Linker 9.00.30729 (Visual Studio 2008) | Consistent with a small, purpose-built C loader; not packed |
| Imports: WININET.dll (`URLDownloadToFileW`, `InternetOpenUrlA/W`, `InternetReadFile`), SHLWAPI.dll, SHELL32.dll (`ShellExecuteW`) | Directly supports HTTP download-and-execute behavior; no crypto/obfuscation API imports observed |
| Overlay: PE overlay present (`overlay number` field non-zero in `portex` output) filled with a repeating literal `PADDING` string plus additional non-ASCII high-entropy-looking bytes trailing the resource section | Likely simple file-size inflation (a common technique to defeat sandbox/AV size-based scan limits); did not decode to a meaningful embedded payload during this pass — flagged as unresolved |
| No TLS directory, normal entrypoint/timestamp/imagebase (per pescan) | No anomalous PE header manipulation |
| yara-forge (45+ source ruleset): no matches | No resemblance to any cataloged family signature |

### Code Analysis

Disassembly and native decompilation (radare2 `pdc`, since the r2ghidra plugin was unavailable in this environment) of `main` and the three worker subroutines confirms the control flow described in the Executive Summary:

- `main` (`0x401530`): `Sleep(2000)` → calls `fcn.00401480` (checks/creates `%TEMP%\525352353.jpg` marker) → if first-run-in-temp: creates mutex `"5886844846"` via `CreateMutexA`, checks `GetLastError()==183 (ERROR_ALREADY_EXISTS)` to enforce single instance → resolves own path (`GetModuleFileNameW`+`PathFindFileNameW`) → strips its own Zone.Identifier ADS → compares own filename to `"winsvcn.exe"`:
  - If **not** already `winsvcn.exe`: `CopyFileW` to `%USERPROFILE%\winsvcn.exe`, `SetFileAttributesW(..., 3)` (READONLY|HIDDEN), `RegOpenKeyExW`/`RegSetValueExW` on `CurrentVersion\Run` with value `"Windows Service Manager"` = new path, `RegCloseKey`, then `ShellExecuteW("open", <new path>)` via helper `fcn.00401070`, and exits.
  - If already `winsvcn.exe` (i.e., running as the persistent copy): calls `fcn.00401120` against `hxxp://178.16.54.109/prel.php` (opens the URL, reads the `HTTP_QUERY_CONTENT_LENGTH` header via `HttpQueryInfoA`, and compares it to a previously-seen value — apparent lightweight version/size check before deciding whether to fetch the payload; note the linear `pdc` decompiler could not fully recover this function's control flow, so this interpretation should be treated as approximate pending a Ghidra-quality decompile), then calls `fcn.004011c0` to download `hxxp://178.16.54.109/vload.exe` via `URLDownloadToFileW` to `%TEMP%\<rand><rand>.exe` (filename built from two `rand()`-derived values via `wsprintfW("%s\%d%d.exe", ...)`, seeded from `GetTickCount`), strips the downloaded file's Zone.Identifier ADS, executes it via the same `ShellExecuteW "open"` helper, then `Sleep(0xDBBA0)` (900,000 ms ≈ 15 minutes) before returning/exiting.
- `fcn.00401000`: a `Sleep(1000)`-gated dummy `InternetOpenA`/`InternetCloseHandle` pair — appears to be a network-availability probe with no further use of the handle; likely a discarded/incomplete connectivity check.
- `fcn.00401070`: generic "launch a file" helper — first tries `CreateProcessW`, falls back to `ShellExecuteW("open", ...)` on failure, with a short retry `Sleep`.
- `fcn.00401480`: `%TEMP%\525352353.jpg` marker-file existence/creation check (masquerades as a JPEG by extension only; contains no image data — it is a zero-length flag file).

All three hardcoded C2/download strings (`prel.php`, `vload.exe`, and the three browser User-Agent strings) are directly referenced (`push`ed) from within `main` and its callees — confirmed live code paths, not vestigial/data-only strings.

## What We Don't Know

- The Stage-2 payload (`vload.exe`) was not retrieved or analyzed — the C2 was not contacted live during this analysis (per OSINT tradecraft: avoid tipping off the adversary / disclosing investigative interest to attacker-controlled infrastructure without prior authorization). Its capabilities, and therefore the ultimate objective of this campaign, are unknown.
- No dynamic/sandbox detonation was performed; the control-flow reconstruction for the C2 check-in function (`fcn.00401120`) relies on radare2's linear `pdc` decompiler (the Ghidra-backed `r2ghidra` plugin was not installed in this environment) and should be treated as approximate, not authoritative.
- The delivery/infection vector for `sample.exe` itself is unknown — no phishing lure, dropper chain, or delivery URL was provided with the sample.
- The purpose of the ~large repeating-`PADDING` overlay and adjoining high-entropy trailing bytes was not decoded; it may be simple sandbox-evasion padding or may conceal additional data.
- No sample hash lookups were performed against VirusTotal/MalwareBazaar/Malpedia/OTX (require API keys not configured in this session) — detection-name corroboration and possible prior public reporting on this exact hash remain unchecked.
- Malware family remains unattributed; only the hosting infrastructure (OMEGATECH/AS202412) is independently corroborated as a known multi-family bulletproof-hosting network, which is a weak (shared-infrastructure) attribution signal, not a code-level one.

## Detection Engineering

| Detection Content | Notes |
|---|---|
| Registry-Run-key value name `"Windows Service Manager"` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` pointing to a file named `winsvcn.exe` in `%USERPROFILE%` | Host-based hunting; false-positive risk is low for this exact value-name string but the Run key location itself is extremely common — pair with the file name/path |
| Outbound HTTP GET requests to `178.16.54.109` for `/prel.php` or `/vload.exe`, or any HTTP request carrying one of the three embedded Chrome UA strings from a process not named `chrome.exe`/a browser | Network-based hunting; treat the bare-IP-over-HTTP pattern (no domain, no TLS) itself as a weak generic signal worth combining with the specific path |
| Presence of zero-byte file `%TEMP%\525352353.jpg` alongside a mutex named `5886844846` | Host artifact combination; individually weak, but the combination is distinctive to this sample family variant |
| Any process stripping the `:Zone.Identifier` ADS from a file it just wrote to `%TEMP%` or `%USERPROFILE%`, immediately followed by `ShellExecuteW`/`CreateProcess` on that same file | Generic MOTW-bypass-then-execute behavioral rule (T1553.005 + T1204) |

## About this Report

| | |
|---|---|
| **Report Title** | Generic HTTP Downloader ("winsvcn.exe" / sample.exe) — CTI Analysis |
| **Author(s) and Organization** | Analyst-assisted (Claude Code + REMnux MCP), for internal use |
| **Publication Date** | 2026-07-26 |
| **Report Classification** | TLP:AMBER |
| **Follow-Up Contact** | lucien.lagarde@gmail.com |

### Report Changelog

| **Date** | **Author** | **Change Description** |
|---|---|---|
| 2026-07-26 | Analyst | Initial report |

## Appendix: Analysis Environment

REMnux (via `remnux` MCP server) at `172.16.183.133`, tools used: `peframe`, `diec`, `capa` (table + `-j` JSON), `pestr`, `portex`, `yara-forge`, `pecheck`, `pescan`, `signsrch`, `autoit-ripper`, `upx -d`, `manalyze`, `1768.py`, `csce`, `redress`, `ssdeep`, `exiftool`, `radare2` (`-A` auto-analysis, `axt` xref listing, `pdc` native decompiler — `r2ghidra`/`pdg` was unavailable in this environment). Analysis depth: standard automated triage followed by targeted manual static/code analysis; no dynamic/sandbox detonation performed. OSINT enrichment performed passively (no sample or URL submitted to any third party): RIPE RDAP, ipinfo.io, Shodan InternetDB, Team Cymru MHR (DNS), and general web search for ASN/hosting-provider context.
