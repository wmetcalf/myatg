# myatg — Windows signature & certificate validator

A self-contained native validator for Windows code-signing. Given a file, it emits a
single JSON record describing the signature, the full certificate chain, the OS trust
verdict, and an optional cert-"graveyard" match. Built to triage untrusted/malicious
files on a worker.

The signature verdict uses `WinVerifyTrust` with `WTD_REVOKE_NONE`, so it is air-gappable
(signtool-parity); revocation is a separate, opt-in layer. x86_64, .NET Framework 4.x.

> 🪦 The name and the "graveyard" theme are a tongue-in-cheek hat tip to
> **[certgraveyard.org](https://certgraveyard.org/)** — the public registry of abused /
> leaked code-signing certs that `myatg` can match a signer against (`--gv`).
> Theme song: [Cleffy — *Meet You At The Graveyard*](https://www.youtube.com/watch?v=dSf_qqI0PjI).

## How it differs from `signtool` / `Get-AuthenticodeSignature`

`myatg` is built for *triaging untrusted files*, not for a build pipeline. The practical
differences from the two standard tools:

- **It folds revocation into the verdict.** `signtool verify` and
  `Get-AuthenticodeSignature` report `Status = Valid` for a file signed with a cert that
  chained to a trusted root but was *later revoked* — neither checks revocation by default.
  `myatg` runs an explicit online `X509Chain` and reports `Revoked`. Across a 1,558-file
  signed-malware corpus this caught **45** files (abused/leaked code-signing certs) that
  `Get-AuthenticodeSignature` called `Valid`. **This is the headline value-add.**
- **Air-gappable signature verdict, separate revocation layer.** The signature check uses
  `WTD_REVOKE_NONE` (signtool-parity, zero network), so *"is the signature cryptographically
  intact?"* needs no egress; revocation is a distinct opt-in layer (`--rev
  online|offline|none`). The two questions are reported separately instead of conflated.
- **CRL/OCSP cache warming (`--warm-cache <dir>`).** Pre-walks a representative sample's
  chains with online revocation to populate the on-disk `CryptnetUrlCache`. Snapshot a warm
  worker afterward and every restored clone inherits a hot cache → revocation serves from
  cache (~tens of ms, no callout) for covered CAs and only live-fetches genuine misses
  through your controlled egress. There is no equivalent in `signtool`/`Get-AuthenticodeSignature`.
- **Microsoft's disallowed kill-list, surfaced.** A cert on the Microsoft Disallowed CTL
  (DigiNotar-class) is reported as `Distrusted` with `explicit_distrust:true`, not lumped
  into a generic failure. `--refresh` updates that kill-list (`syncWithWU` + installs the
  disallowed store) as part of the tool's own update path.
- **One structured JSON record per file**, not objects/text — a superset of CAPE's
  `digital_signers`: adds `tbs_sha1`/`tbs_sha256`, per-cert EKU, the full leaf→root chain,
  and ASN.1-parsed CDP/AIA URLs that the in-VM `signtool` (`aux_sha1` only) lacks.
- **Cert-graveyard matching (`--gv`).** Matches the signer against a CSV of known-abused
  certs on `tbs_sha256` / thumbprint / serial / file-SHA256. Neither standard tool does this.
- **More than PE/MSI.** RDP (`.rdp`) gets a full `rdpsign` crypto-verify **plus signscope
  coverage** — which dangerous settings are present-but-unsigned (the APT29 lure vector).
  `signtool`/`Get-AuthenticodeSignature` don't validate RDP at all.
- **Deterministic on malformed signatures.** `Get-AuthenticodeSignature` can return a
  different `Status` across runs on malformed-sig malware; the `WinVerifyTrust` verdict is
  stable.
- **No dependencies.** A single native `.exe` (in-box .NET Framework, no SDK; the binary
  path needs no PowerShell) vs. a PowerShell cmdlet.

For **scripts** (`.vbs`/`.js`/`.ps1`) `myatg` intentionally takes its *status* from
`Get-AuthenticodeSignature` (the OS is the authority there) and wraps it with the structured
signer/chain/graveyard metadata — a superset on that path, not a replacement.

## Build

No SDK or external dependencies — `myatg` compiles with the in-box C# compiler that ships
with every Windows install. Two source files, one command:

```
csc.exe /nologo /r:System.Security.dll /out:myatg.exe myatg.cs rdp_validate.cs
```

- Compiler path: `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`.
- Runs on any Windows **x64** with **.NET Framework ≥ 4.5** (in-box on Server 2016 /
  Windows 10 and later).
- Or download the precompiled `myatg.exe` from a release.

## Supported formats

| Format | How it's verified |
|--------|-------------------|
| PE (`.exe`/`.dll`) | `WinVerifyTrust` — embedded, then catalog fallback |
| MSI, CAB | `WinVerifyTrust` |
| Scripts (`.vbs`/`.js`/`.ps1`) | `Get-AuthenticodeSignature` (OS truth); native signer-cert extraction for metadata |
| RDP (`.rdp`) | Full crypto-verify of the `rdpsign` canonical content + signscope coverage |

## Usage

```
myatg.exe <file> [flags]
```

Reads one file, writes one line of JSON to **stdout** (warnings/errors to **stderr**), exits 0.

### Examples

```sh
# basic — validate a file, JSON verdict on stdout
myatg.exe C:\samples\suspect.exe

# match the signer against a cert-graveyard CSV
myatg.exe --gv C:\intel\bad_certs.csv C:\samples\suspect.dll

# air-gapped: skip all revocation network calls
myatg.exe --rev none C:\samples\suspect.exe

# refresh MS roots + disallowed kill-list (admin), then validate
myatg.exe --refresh
myatg.exe C:\samples\suspect.exe

# raise the size cap to 1 GB for a large installer; validate an RDP lure
myatg.exe --max-size 1024 C:\samples\big_installer.msi
myatg.exe C:\samples\lure.rdp
```

### Flags

| Flag | Meaning |
|------|---------|
| `--gv <csv>` | Cert-graveyard CSV (see below) |
| `--rev online\|offline\|none` | Revocation mode (default `online`) |
| `--scripts ps\|native` | Script verification path (default `ps`) |
| `--max-size <MB>` | Input-size cap (default 500; also `VALIDATOR_MAX_SIZE_MB` env; flag wins) |
| `--refresh` | Clear CRL/OCSP cache + `syncWithWU` (installs MS roots **and** the disallowed kill-list into the Disallowed store) |
| `--warm-cache <dir>` | Pre-warm the CRL/OCSP cache from a representative sample dir |
| `--iters <N>` | Repeat N times (benchmarking) |

## Output (JSON)

Always emits the same field set (error/oversize cases too, with null/empty values):
`file_sha256, status, signature_type, content_verified, is_os_binary, signer, chain,
graveyard, timestamped, sign_time, timestamper, ms`.

`status` ∈ `Valid, NotSigned, HashMismatch, Revoked, Distrusted, UntrustedRoot, Expired
(RDP), UnknownError`.

`chain.chain[]` is the full leaf→intermediate→root list. Each cert (and `signer`) carries:
`subject(+_cn), issuer(+_cn), serial_number, thumbprint, md5/sha1/sha256_fingerprint,
tbs_sha1/tbs_sha256, not_before/after, eku[], eku_codesigning, self_signed,
crl_urls[], ca_issuer_urls[], ocsp_urls[]`. This is a superset of CAPE's `digital_signers`
(adds the tbs hashes / EKU / OS-trust verdict that the in-VM signtool lacks). CDP/AIA URLs
are ASN.1-parsed (not regex), and reported verbatim — including any quirks baked into the
cert (e.g. a trailing `%20` in some Microsoft CDP URLs).

## Cert graveyard

External CSV, pointed at via `--gv`. Columns: `Hash, Serial, Thumbprint, TBS SHA256,
Malware, Malware Type`. Matched in precedence order tbs_sha256 → thumbprint → serial →
file_sha256, surfaced as `graveyard{hit, matched_on, malware, malware_type}`. The tool does
**not** fetch or update the CSV — curation is external (operator/pipeline). It is loaded
once at process start, so in a warm/recycled process a CSV change needs a recycle.

This is distinct from the Microsoft **disallowed** kill-list, which the tool *does* update
(`--refresh` → `syncWithWU` → Disallowed store) and which `X509Chain` enforces for free,
surfaced as `chain.explicit_distrust` / `status: Distrusted`.

## Known limitations / behavior

- **Catalog signatures are host-OS-resident (cross-OS inconsistency).** Most Windows OS
  binaries are *catalog*-signed: the signature is not in the file, it lives in a `.cat` in
  the host's `CatRoot` store. This validator's catalog lookup
  (`CryptCATAdminEnumCatalogFromHash`) only sees the **local** host's catalogs. So a file
  whose catalog is not installed on *this* host — e.g. a **Windows 11** catalog-signed
  binary validated on a **Server 2025** worker — is reported `NotSigned` even though it is
  legitimately signed on its home OS. **Embedded-signed files are unaffected** (the
  signature is self-contained and Microsoft roots ship on every Windows), so all
  embedded-signed binaries — including essentially all *signed malware* — validate
  correctly regardless of the worker's OS. The gap is confined to legitimate,
  catalog-signed OS components.
  - Consequence for `is_os_binary`: it is a heuristic (`signature_type == "Catalog"` AND a
    Microsoft subject), so a cross-OS catalog binary that fails catalog lookup is also
    `is_os_binary=false`, and embedded Microsoft binaries are not flagged either.
  - Mitigations if cross-OS OS-binary detection matters: validate catalog-signed files on a
    patched matching-OS guest (the catalog is current there by construction), or stage that
    OS's `CatRoot` on the worker. **Note that statically harvesting catalogs from install
    media goes stale** — Windows Update ships new catalogs for patched system binaries, so a
    fixed catalog pack only validates the as-shipped versions. There is no consolidated
    public catalog repository to consume; keeping catalogs current effectively requires a
    patched OS instance.

- **`is_os_binary` is a heuristic**, not the OS `IsOSBinary` flag the PowerShell reference
  uses.

- **Scripts** route their trust verdict to `Get-AuthenticodeSignature` (shells
  `powershell.exe`) — OS-accurate, but adds latency vs the pure-native binary path. The
  native script SIP path (`--scripts native`) is experimental and not authoritative.

- **Online revocation** only reaches the network for chains that build to a *trusted* root
  (CryptoAPI gates the fetch on trust); untrusted/attacker certs trigger no outbound
  request. So `--rev online` does not leak for the malware case.

- **`--warm-cache` makes outbound requests.** It deliberately builds chains with online revocation to pre-warm the CRL/OCSP cache, so it fetches the CDP/AIA URLs embedded in *every* cert of *every* file in the directory — including attacker-controlled URLs in malicious certs. Operator-invoked + intended, but a network side-effect to note in sensitive environments.
- **x86_64 only** (P/Invoke struct offsets are 64-bit).

## License

MIT — see [`LICENSE`](LICENSE). No third-party dependencies; `myatg` uses only the .NET
Framework BCL and Windows platform APIs. RDP signing-format reverse-engineering credit:
[nfedera/rdpsign](https://github.com/nfedera/rdpsign).
