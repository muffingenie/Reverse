# Malware Analysis Report — sample.exe (First-Stage Downloader, "actami")

**TLP:AMBER** — contains an active third-party C2/hosting IP and download URL. Handle per your organization's sharing policy.

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
- [About this Report](#about-this-report)
- [Appendix: Analysis Environment](#appendix-analysis-environment)

## Executive Summary

`sample.exe` is a native, unpacked 64-bit Windows GUI executable compiled with Microsoft Visual C++ (Visual Studio 2022, v17.6). Static and code cross-reference analysis show it is a first-stage downloader: at startup it resolves the current user's `%LOCALAPPDATA%` directory via `SHGetFolderPathA`, generates a randomized alphanumeric string (drawn from the charset `abcdefghijklmnopqrstuvwxyz0123456789`) to name a working directory/file, and contains a hard-coded, code-referenced URL — `http://95.164.53.193:5001/actami.exe` — used with the imported `URLDownloadToFileA` (urlmon.dll) API. The binary also imports `ShellExecuteExA`, consistent with launching a downloaded second-stage payload, and references a `\Service.exe` filename string, suggesting the retrieved payload may be dropped/renamed to masquerade as a Windows service binary. No packer, obfuscator, or .NET/AutoIt runtime was found — despite generic triage tags suggesting UPX/AutoIt, both `upx -d` and `autoit-ripper` failed to find any such container, indicating those were false-triage signals rather than confirmed packing. The unresolved compiler PDB path (`C:\Users\Administrator\source\repos\actami\x64\Release\actami.pdb`) names the project "actami," matching the payload filename in the embedded URL — an internal, self-consistent but still attacker-supplied artifact, not independent confirmation. No YARA family signature matched this sample, and no established malware family could be confirmed from code, behavior, or OSINT; this appears to be a custom/bespoke or unattributed downloader rather than a recognized commodity family. The C2/hosting IP (95.164.53.193) resolves to a VPS at "QWINS LTD" (AS213702) in Frankfurt, Germany, with SSH exposed (Ubuntu + OpenSSH 8.9p1) — consistent with a rented VPS used to stage a payload, not a compromised legitimate host.

## Sample Snapshot

| | |
|---|---|
| **Malware Family** | Unidentified / unattributed. No YARA family match; no confirmed vendor or code-reuse hit. Filename "actami" (from PDB path and embedded URL) is an unconfirmed, attacker-supplied lead only — **low confidence** in any specific family label. |
| **Key Capabilities** | HTTP download (URLDownloadToFileA) of a second-stage payload from a hard-coded IP; process launch of the retrieved file (ShellExecuteExA); randomized working-directory/filename generation in `%LOCALAPPDATA%`; locale/environment discovery. |
| **Target Platform** | Windows x86-64 (PE32+ GUI subsystem), native C/C++, no managed runtime (.NET) or scripting engine required. |
| **Primary Artifact** | `sample.exe`, SHA-256 `2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f` |
| **Infection Vector** | Unknown — sample was provided directly for analysis; no delivery/email/lure artifact was present in the file itself. |

## Malware Family Identification

| Family | Basis | Confidence |
|---|---|---|
| None identified | yara-forge (45+ source ruleset) produced no family match; no code-reuse or vendor corroboration available (no VirusTotal/MalwareBazaar key access in this analysis) | N/A |
| "actami" (unconfirmed project/campaign name) | PDB path `...\repos\actami\x64\Release\actami.pdb` and matching filename in the embedded download URL (`.../actami.exe`) | Low — self-consistent internal naming only, not third-party corroborated |

Per ICD-203 convention, this report has **low** confidence in any family attribution and treats "actami" strictly as an internal/developer project name, not a confirmed threat-actor or campaign label.

## Component Inventory

| Role | File Name | File Type | Notes |
|---|---|---|---|
| First-stage downloader | sample.exe | PE32+ (x86-64) GUI EXE | Only artifact provided; second-stage payload (`actami.exe` / possible `Service.exe`) was not recovered — the C2 host was not fetched during this analysis |

## Runtime Requirements

- Architecture: x86-64 (PE32+), Windows GUI subsystem (`IMAGE_SUBSYSTEM_WINDOWS_GUI`)
- Statically linked CRT (no external MSVC runtime DLL dependency beyond standard system DLLs)
- Imports: `KERNEL32.dll`, `USER32.dll`, `SHELL32.dll` (`ShellExecuteExA`, `SHGetFolderPathA`), `urlmon.dll` (`URLDownloadToFileA`)
- No TLS callbacks; no .NET (`mscoree.dll` reference present only as a delay-load stub typical of MSVC binaries, not evidence of managed code)
- Requires outbound HTTP (port 5001) reachability to the embedded IP to complete its function
- Manifest requests `asInvoker` execution level (no UAC elevation requested) and declares `SegmentHeap`

## Sources

Sample was supplied directly for analysis at `/home/remnux/files/samples/sample.exe` (REMnux VM). No prior telemetry, partner sharing, or first-seen timestamp was available. OSINT enrichment was performed only against derived, non-sample indicators (IP `95.164.53.193`) using keyless services (Shodan InternetDB, SANS ISC/DShield, ipinfo); no sample hash lookup was possible against a keyless source (Team Cymru MHR endpoint used in this workflow returned no data), and no VirusTotal/MalwareBazaar/OTX key was available in this session.

## Capabilities

The sample's behavior centers on **Command and Control staging / payload delivery** and **Discovery**, with no evidence in this analysis of persistence, credential access, or destructive impact.

| MBC Behavior | Procedure Observed | Notes |
|---|---|---|
| Download and execute (C0007 / Ingress Tool Transfer) | `URLDownloadToFileA` call reachable from `entry0`, targeting hard-coded URL `http://95.164.53.193:5001/actami.exe`; string confirmed code-referenced via `lea rdx, str.http://...` at `0x14000283f` | ATT&CK T1105 (Ingress Tool Transfer). Confirmed as reachable code, not just a data-only string. Execution at runtime not dynamically verified. |
| File System – directory/path discovery | `SHGetFolderPathA(CSIDL_LOCAL_APPDATA=0x1c)` at `0x140002883`, then builds a path under `C:\Users\Default\AppData\Local` | ATT&CK T1083. Confirmed via disassembly. |
| Random name/path generation | Randomized 1–2 character alphanumeric generation using charset `abcdefghijklmnopqrstuvwxyz0123456789` (mod-36 indexing against a random seed) to build a working directory or filename | Consistent with evading static file-path/name-based detection. |
| Process execution | `ShellExecuteExA` imported (SHELL32.dll) | Import confirmed; specific invocation site/arguments not traced in this pass — treat as artifact pending full code-flow confirmation. |
| Discovery – locale/environment | Imports `GetLocaleInfoEx`, `LocaleNameToLCID`, environment variable query APIs; capa matched "get geographical location" / "query environment variable" | Consistent with basic environment/region fingerprinting prior to payload delivery; could also be ordinary CRT/locale-handling code common to MSVC binaries — **not confirmed as targeting logic**. |
| Data obfuscation (RC4-like) | capa matched "encrypt data using RC4 PRGA" at `0x140004da0` | **Artifact only in this pass** — not traced to a confirmed input/output (e.g., network buffer vs. internal string). Flag for follow-up. |
| Persistence — "schedule task via at" (capa match) | capa flagged this rule at `0x140002810`, which code inspection shows is actually the *download/path-building* function (SHGetFolderPathA + URL string), with **no** Task Scheduler / `at` / `mstask` API imports anywhere in the import table | **Likely false positive** — capa's generic instruction-pattern match does not correspond to any persistence-capable API. Not reported as a confirmed capability. |

## Indicators of Compromise

Defanged per convention.

| Type | Indicator | Context |
|---|---|---|
| Hash Values | SHA-256: `2880c19f853059bae15a838d1320f728d3f681ff8bdfe22d455bc0335d317c7f`<br>SHA-1: `2a67068602cd24a96338010fb040eccd08b60aa3`<br>MD5: `a5cd6f31554350d552c42dc0320c85cb`<br>ssdeep: `3072:P53+Z2c90aq86nJ4YvsaLuiv0SQyd9sODvm3klPnR8YQpl29p8:P53+Zz6JD0Gugdd9bvf/OC9p` | First-stage downloader (only component recovered) |
| IP Addresses | `95.164.53[.]193` | Download host, port 5001; VPS at "QWINS LTD" (AS213702), Frankfurt, DE; hostname `vm164971.hosted-by.qwins[.]co`; SSH (OpenSSH 8.9p1 / Ubuntu) exposed on port 22 |
| Domain Names | `vm164971.hosted-by.qwins[.]co` | Reverse-DNS hostname of the C2/hosting IP (not resolved from the binary itself) |
| Network Artifacts | `hxxp://95.164.53[.]193:5001/actami.exe` | Full download URL, confirmed code-referenced (not merely a data-only string) |
| Host Artifacts | PDB path: `C:\Users\Administrator\source\repos\actami\x64\Release\actami.pdb`<br>Filename reference: `\Service.exe`<br>Drop-directory base: `C:\Users\Default\AppData\Local` | Developer/build artifact; possible masquerade filename for the retrieved payload; base directory for randomized working folder |

## Analysis Details

### Automated Analysis

Analysis was performed via the REMnux MCP `analyze_file` (standard depth) auto-triage, which ran 17 tools (peframe, diec, capa, pestr, portex, yara-forge, pecheck, pescan, signsrch, autoit-ripper, upx-decompress, manalyze, 1768.py, csce, redress, ssdeep, exiftool) plus targeted follow-up (`r2` disassembly, `verify_string_usage`). autoit-ripper and upx-decompress both errored (no AutoIt resource / no valid UPX header found), correcting the auto-triage's initial "AutoIt compiled | UPX packed" heuristic tags as false positives.

### Static Properties Analysis

| Property | Significance |
|---|---|
| PE32+ x86-64, GUI subsystem, 7 sections, MSVC 19.36.36252 / Linker 14.36.36252 (VS2022 17.6) | Standard native MSVC build; no compiler/linker anomaly |
| No packer detected (diec: clean Microsoft Linker/Compiler/Tool detection only; UPX/AutoIt attempts both failed) | Sample is not packed — strings and imports are directly visible, which is why the C2 URL and PDB path are plainly recoverable |
| `pescan`: "imagebase: suspicious" | Non-default image base is common and not independently indicative of malice; noted for completeness |
| No YARA family signature match (yara-forge, 45+ source rulesets) | No resemblance to a cataloged family at the static-signature level |
| Embedded PDB path names project "actami" | Matches the payload filename in the embedded URL — self-consistent developer/build artifact, useful as an internal tracking label but not external attribution |
| capa: 17 capability rules matched (download URL, create directory, write file, create/terminate process, PEB access, change memory protection, environment/locale discovery, RC4 PRGA, "schedule task via at") | Several matches (RC4, "schedule task via at", geographic location) are capa pattern-level hits not yet confirmed against reachable, executed code — see Capabilities table caveats |

### Behavioral Analysis

Dynamic detonation (sandbox/emulation) was **not performed** in this pass — see [What We Don't Know](#what-we-dont-know). All capability claims below are static/code-reachability findings, not confirmed runtime behavior.

### Code Analysis

The function at `0x140002810` (called from `entry0` at `0x140004cd4`) is the core downloader logic:

1. `0x140002883` — calls `SHGetFolderPathA(NULL, 0x1c /* CSIDL_LOCAL_APPDATA */, NULL, 0, pszPath)`, falling back to the literal string `C:\Users\Default\AppData\Local` if the call fails (`test eax,eax; jne ...`).
2. `0x14000290b`–`0x140002924` — loads the charset string `abcdefghijklmnopqrstuvwxyz0123456789` (36 chars) and repeatedly divides a value by 36 (`div rbx`) to index into it, building a short randomized alphanumeric string (classic modulo-based random name generator) — used to construct a unique subdirectory or filename under the resolved `%LOCALAPPDATA%` path.
3. `0x14000283f` — loads the address of the string `http://95.164.53.193:5001/actami.exe` into `rdx`, immediately ahead of a call sequence that (per capa and pestr import data) leads into `URLDownloadToFileA`.
4. `ShellExecuteExA` is imported but its specific call site/arguments were not traced to completion in this pass (flagged for follow-up).

This confirms the C2 URL is **reachable from executable code**, not a dead/vestigial string (per `verify_string_usage`: `xref_status: referenced_from_code`, one code cross-reference at `0x14000283f`).

## What We Don't Know

- The sample was not detonated dynamically (no sandbox/emulation run in this pass) — the download → save → execute chain is established via static code reachability only, not confirmed execution.
- The second-stage payload (`actami.exe`, potentially renamed to `Service.exe`) was not retrieved or analyzed; its capabilities, persistence mechanism, and true purpose are unknown.
- The capa matches for "encrypt data using RC4 PRGA," "get geographical location," and "schedule task via at" were spot-checked but not fully traced to confirmed executed behavior; the "schedule task via at" match specifically appears to be a false positive (matched code turned out to be the download function, with no Task Scheduler API imports present anywhere in the binary).
- No hash reputation could be obtained from a keyless source in this session (Team Cymru MHR endpoint used did not return results); no VirusTotal/MalwareBazaar/OTX/Malpedia key was available to check third-party detections, related samples, or family attribution.
- Delivery/infection vector is unknown — no phishing lure, document, or dropper chain preceding this executable was provided or found.
- Whether `95.164.53.193:5001` is still live and serving `actami.exe` at time of reading was not verified (avoided a live fetch to prevent tipping off the operator during this triage).

## About this Report

| | |
|---|---|
| **Report Title** | sample.exe — First-Stage Downloader ("actami") CTI Report |
| **Author(s) and Organization** | Generated via Claude Code + REMnux MCP, for Lucien Lagarde |
| **Publication Date** | 2026-07-25 |
| **Report Classification** | TLP:AMBER |
| **Follow-Up Contact** | lucien.lagarde@gmail.com |

### Report Changelog

| **Date** | **Author** | **Change Description** |
|---|---|---|
| 2026-07-25 | Claude Code | Initial report |

## Appendix: Analysis Environment

Analysis performed on REMnux (via `remnux` MCP server) against `/home/remnux/files/samples/sample.exe`. Tools: peframe, diec, capa 9.3.1, pestr, portex, yara-forge, pecheck, pescan, signsrch, autoit-ripper, upx, manalyze, 1768.py, csce, redress, ssdeep, exiftool, radare2 6.0.8 (`aa` analysis level; deeper `aaa` was not required). Depth: `standard` auto-triage plus targeted manual disassembly of the identified downloader function. OSINT lookups (Shodan InternetDB, SANS ISC/DShield, ipinfo, crt.sh) were run directly, keyless, against the derived IP indicator only — the sample itself was never uploaded or executed outside the REMnux sandbox.
