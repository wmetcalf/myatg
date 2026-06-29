# myatg — Windows signature & certificate validator

A self-contained native validator for Windows code-signing. Given a file, it emits a
single JSON record describing the signature, the full certificate chain, the OS trust
verdict, and an optional cert-"graveyard" match. Built to triage untrusted/malicious
files on a worker.

The signature verdict uses `WinVerifyTrust` with `WTD_REVOKE_NONE`, so it is air-gappable
(signtool-parity); revocation is a separate, opt-in layer. x86_64, .NET Framework 4.x.

> 🪦 **myatg** = "**M**eet **Y**ou **A**t **T**he **G**raveyard" (the
> [Cleffy track](https://www.youtube.com/watch?v=dSf_qqI0PjI)) — a tongue-in-cheek hat tip to
> **[certgraveyard.org](https://certgraveyard.org/)**, the public registry of abused / leaked
> code-signing certs that `myatg` can match a signer against (`--gv`).

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

## Serve modes (persistent validator)

For high throughput, run myatg as a **warm, persistent validator** instead of forking a
process per file — the CLR JIT and the trust/CRL caches stay hot across files. The verdict
JSON is byte-identical to the one-shot path.

**stdin mode** — one file **path** per line on stdin, one JSON verdict line back:

```sh
myatg.exe --serve
```

**HTTP mode** — POST file **bytes** to a loopback endpoint, get the same JSON verdict:

```sh
myatg.exe --serve-http --port 8137
```

Endpoints:

- `GET  /healthz`  → `{"ok":true}` (no auth)
- `POST /validate` → body = raw file bytes; returns the verdict JSON.
  Optional query overrides: `?rev=online|offline|none`, `?scripts=ps|native`.

```sh
curl --data-binary @sample.exe http://127.0.0.1:8137/validate
```

**Serve flags:** `--bind <addr>` (default `127.0.0.1`), `--port <n>` (default `8137`),
`--token <secret>` (require `Authorization: Bearer <secret>`), `--allow-insecure` (permit a
non-loopback bind without a token — not recommended). **Binding a non-loopback address
without `--token` refuses to start.** `--gv` / `--max-size` / `--rev` / `--scripts` are read
once at startup and apply to the whole server (`--rev` / `--scripts` can be overridden
per request via query string).

**As a least-privilege Windows service** (run once, elevated):

```sh
myatg.exe --install-service --port 8137
```

Creates service `myatg` under the virtual account `NT SERVICE\myatg`, reserves the loopback
URL (`netsh http add urlacl`) scoped to that account, and sets auto-start + restart-on-failure.
The service itself then runs unelevated. Remove it with:

```sh
myatg.exe --uninstall-service --port 8137
```

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

## Examples (real MalwareBazaar samples)

Complete, unmodified `myatg.exe` JSON output on one sample per supported format — every one a live MalwareBazaar sample. Expand each block for the full record (full leaf→root chain and all fields). Family labels are MalwareBazaar's tags unless noted.

### DLL — [`Green.dll`](https://bazaar.abuse.ch/sample/03012e22602837132c4611cac749de39fb1057a8dead227594d4d4f6fb961552/) · revoked (OysterLoader)

Signed with a short-lived "NEW VISION MARKETING LLC" cert issued through Microsoft's ID-Verified code-signing program, then **revoked** days later. `signtool` / `Get-AuthenticodeSignature.Status` report it `Valid` (they don't check revocation); myatg flags it `Revoked` and the cert-graveyard match (`--gv`, from [certgraveyard.org](https://certgraveyard.org/)) tags **OysterLoader**.

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file_sha256": "03012e22602837132c4611cac749de39fb1057a8dead227594d4d4f6fb961552",
  "status": "Revoked",
  "signature_type": "Embedded",
  "content_verified": true,
  "is_os_binary": false,
  "signer": {
    "subject": "CN=NEW VISION MARKETING LLC, O=NEW VISION MARKETING LLC, L=Mesa, S=Arizona, C=US",
    "subject_cn": "NEW VISION MARKETING LLC",
    "issuer": "CN=Microsoft ID Verified CS AOC CA 01, O=Microsoft Corporation, C=US",
    "issuer_cn": "Microsoft ID Verified CS AOC CA 01",
    "serial_number": "3300043B67E4F8C74D2C120775000000043B67",
    "thumbprint": "51BB5BAEB3D293332FAB7E9A4CC23F406AFB0D94",
    "md5_fingerprint": "018955ffdd962cb5dea1412e1e47aaeb",
    "sha1_fingerprint": "51bb5baeb3d293332fab7e9a4cc23f406afb0d94",
    "sha256_fingerprint": "ea939fe29ce11aa1586669e98228c420042a45dd770fe7cf3b6704a0cde6312e",
    "tbs_sha1": "8570e34cd1908e63f2c5e98ca2358c2bf6d1fcd4",
    "tbs_sha256": "da3b081a9b9b43f3d966e3f72175d7f2fa4f29ef8257f471d03d47afc226e176",
    "not_before": "2025-06-25T06:35:01.0000000Z",
    "not_after": "2025-06-28T06:35:01.0000000Z",
    "eku": [
      "1.3.6.1.4.1.311.97.1.0",
      "1.3.6.1.5.5.7.3.3",
      "1.3.6.1.4.1.311.97.551301807.760330144.701107510.452797528"
    ],
    "eku_codesigning": true,
    "self_signed": false,
    "crl_urls": [
      "http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crl"
    ],
    "ca_issuer_urls": [
      "http://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crt"
    ],
    "ocsp_urls": [
      "http://oneocsp.microsoft.com/ocsp"
    ]
  },
  "chain": {
    "chain_builds": false,
    "chains_to_trusted_root": true,
    "revoked": true,
    "explicit_distrust": false,
    "revocation_checked": "online",
    "valid_at_sign_time": false,
    "chain_length": 4,
    "chain": [
      {
        "subject": "CN=NEW VISION MARKETING LLC, O=NEW VISION MARKETING LLC, L=Mesa, S=Arizona, C=US",
        "subject_cn": "NEW VISION MARKETING LLC",
        "issuer": "CN=Microsoft ID Verified CS AOC CA 01, O=Microsoft Corporation, C=US",
        "issuer_cn": "Microsoft ID Verified CS AOC CA 01",
        "serial_number": "3300043B67E4F8C74D2C120775000000043B67",
        "thumbprint": "51BB5BAEB3D293332FAB7E9A4CC23F406AFB0D94",
        "md5_fingerprint": "018955ffdd962cb5dea1412e1e47aaeb",
        "sha1_fingerprint": "51bb5baeb3d293332fab7e9a4cc23f406afb0d94",
        "sha256_fingerprint": "ea939fe29ce11aa1586669e98228c420042a45dd770fe7cf3b6704a0cde6312e",
        "tbs_sha1": "8570e34cd1908e63f2c5e98ca2358c2bf6d1fcd4",
        "tbs_sha256": "da3b081a9b9b43f3d966e3f72175d7f2fa4f29ef8257f471d03d47afc226e176",
        "not_before": "2025-06-25T06:35:01.0000000Z",
        "not_after": "2025-06-28T06:35:01.0000000Z",
        "eku": [
          "1.3.6.1.4.1.311.97.1.0",
          "1.3.6.1.5.5.7.3.3",
          "1.3.6.1.4.1.311.97.551301807.760330144.701107510.452797528"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crl"
        ],
        "ca_issuer_urls": [
          "http://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crt"
        ],
        "ocsp_urls": [
          "http://oneocsp.microsoft.com/ocsp"
        ]
      },
      {
        "subject": "CN=Microsoft ID Verified CS AOC CA 01, O=Microsoft Corporation, C=US",
        "subject_cn": "Microsoft ID Verified CS AOC CA 01",
        "issuer": "CN=Microsoft ID Verified Code Signing PCA 2021, O=Microsoft Corporation, C=US",
        "issuer_cn": "Microsoft ID Verified Code Signing PCA 2021",
        "serial_number": "3300000007378C5BA1D95B8CD4000000000007",
        "thumbprint": "D7B1118AFBB879D9F2F8E98B9AC12F9367FACE88",
        "md5_fingerprint": "f475601456a47ea6e4bae773db9364df",
        "sha1_fingerprint": "d7b1118afbb879d9f2f8e98b9ac12f9367face88",
        "sha256_fingerprint": "7ee1f718cae6b4d25d10115a367d84b7704e06bd6f8b498825fd42c852574be9",
        "tbs_sha1": "13fafeb733117f82f06b2b303f4b2c102205a561",
        "tbs_sha256": "ff2ff1f9fbc9d9793af4ae35ea053257aa433ff7fcce71f26ed1cad2e30b0fe8",
        "not_before": "2021-04-13T17:31:54.0000000Z",
        "not_after": "2026-04-13T17:31:54.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [
          "http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl"
        ],
        "ca_issuer_urls": [
          "http://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt"
        ],
        "ocsp_urls": [
          "http://oneocsp.microsoft.com/ocsp"
        ]
      },
      {
        "subject": "CN=Microsoft ID Verified Code Signing PCA 2021, O=Microsoft Corporation, C=US",
        "subject_cn": "Microsoft ID Verified Code Signing PCA 2021",
        "issuer": "CN=Microsoft Identity Verification Root Certificate Authority 2020, O=Microsoft Corporation, C=US",
        "issuer_cn": "Microsoft Identity Verification Root Certificate Authority 2020",
        "serial_number": "330000000787A334A37BA58E1C000000000007",
        "thumbprint": "8E750F459DAF9A79D6370DB747AD2226866AD818",
        "md5_fingerprint": "01f8f619255cb2090ece811ab65d88ce",
        "sha1_fingerprint": "8e750f459daf9a79d6370db747ad2226866ad818",
        "sha256_fingerprint": "3d29798cc5d3f0644a7e0dc9cb1cade523ea5ec83b335109b605bfeaa7d5f5c1",
        "tbs_sha1": "4f59e4d45f218b6495b4472b6b629b8ea1e4eaee",
        "tbs_sha256": "33100df4cadaab7a1d369e1fef6c97d865bfb5039387c6bc886e7245bafc5bb8",
        "not_before": "2021-04-01T20:05:20.0000000Z",
        "not_after": "2036-04-01T20:15:20.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [
          "http://www.microsoft.com/pkiops/crl/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crl"
        ],
        "ca_issuer_urls": [
          "http://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt"
        ],
        "ocsp_urls": [
          "http://oneocsp.microsoft.com/ocsp"
        ]
      },
      {
        "subject": "CN=Microsoft Identity Verification Root Certificate Authority 2020, O=Microsoft Corporation, C=US",
        "subject_cn": "Microsoft Identity Verification Root Certificate Authority 2020",
        "issuer": "CN=Microsoft Identity Verification Root Certificate Authority 2020, O=Microsoft Corporation, C=US",
        "issuer_cn": "Microsoft Identity Verification Root Certificate Authority 2020",
        "serial_number": "5498D2D1D45B1995481379C811C08799",
        "thumbprint": "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",
        "md5_fingerprint": "be954f16012122448ca8bc279602acf5",
        "sha1_fingerprint": "f40042e2e5f7e8ef8189fed15519aece42c3bfa2",
        "sha256_fingerprint": "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270",
        "tbs_sha1": "a6a068b26a0feb4f95675d1a95b4c92eba9cd265",
        "tbs_sha256": "a9062454a2789bf77b7734c53721644a21ed4a34d44777406612db4987461222",
        "not_before": "2020-04-16T18:36:16.0000000Z",
        "not_after": "2045-04-16T18:44:40.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "graveyard": {
    "hit": true,
    "matched_on": "cert_tbs_sha256",
    "malware": "OysterLoader",
    "malware_type": ""
  },
  "timestamped": true,
  "sign_time": "2025-06-25T06:48:10.6100000Z",
  "sign_time_verified": true,
  "timestamper": {
    "subject": "CN=Microsoft Public RSA Time Stamping Authority, OU=nShield TSS ESN:491A-05E0-D947, OU=Microsoft Ireland Operations Limited, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
    "subject_cn": "Microsoft Public RSA Time Stamping Authority",
    "issuer": "CN=Microsoft Public RSA Timestamping CA 2020, O=Microsoft Corporation, C=US",
    "issuer_cn": "Microsoft Public RSA Timestamping CA 2020",
    "serial_number": "330000004EA3C60E3E31C3742700000000004E",
    "thumbprint": "932991FBEFC8C69DBF2D1E24AAB94D4292EA0619",
    "md5_fingerprint": "1a2599856cd0276ffbd76145af3b50c3",
    "sha1_fingerprint": "932991fbefc8c69dbf2d1e24aab94d4292ea0619",
    "sha256_fingerprint": "6fb2a7d3ef28051db0defd38f74029f6e491c3b94860cad34f45bebbff964a17",
    "tbs_sha1": "3489f51e3ea0cacaffd0db7e5564b2c816760c7a",
    "tbs_sha256": "3d9b5ef99482fa2bb4e7be2627e8cbc467bca91568d6f3c5e74a74006c9300cf",
    "not_before": "2025-02-27T19:40:17.0000000Z",
    "not_after": "2026-02-26T19:40:17.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.8"
    ],
    "eku_codesigning": false,
    "self_signed": false,
    "crl_urls": [
      "http://www.microsoft.com/pkiops/crl/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crl"
    ],
    "ca_issuer_urls": [
      "http://www.microsoft.com/pkiops/certs/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crt"
    ],
    "ocsp_urls": []
  },
  "ms": 2054
}
```
</details>

### EXE — [`USDC_Case_47293-A3_Notice.exe`](https://bazaar.abuse.ch/sample/0e67b9f5990e3237579b9d11ebd166ee211f6245560b5d2e373f1215031038a3/) · revoked (SimpleHelp)

A phishing-lure filename; the "SimpleHelp Ltd" RMM cert was revoked years after signing — the chain still reaches a trusted root, but `revoked: true`.

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file_sha256": "0e67b9f5990e3237579b9d11ebd166ee211f6245560b5d2e373f1215031038a3",
  "status": "Revoked",
  "signature_type": "Embedded",
  "content_verified": true,
  "is_os_binary": false,
  "signer": {
    "subject": "CN=SimpleHelp Ltd, O=SimpleHelp Ltd, L=BURNTISLAND, C=GB",
    "subject_cn": "SimpleHelp Ltd",
    "issuer": "CN=thawte SHA256 Code Signing CA, O=\"thawte, Inc.\", C=US",
    "issuer_cn": "thawte SHA256 Code Signing CA",
    "serial_number": "51F83A8F29E96230568FBF2B05C27C77",
    "thumbprint": "0C1C560A51457A4D5BA378D389A9B0FF243BAE13",
    "md5_fingerprint": "1de867bf3b9205b591a8528503c7f4fc",
    "sha1_fingerprint": "0c1c560a51457a4d5ba378d389a9b0ff243bae13",
    "sha256_fingerprint": "8db44d50b25ba747234dfc8a4590a5790f331fb0022f61b0b660fa17b9bad752",
    "tbs_sha1": "acf2e617fe614c5e46194d58e774b9d01bcdaf15",
    "tbs_sha256": "a7e21bcb34e6eb3f36cb06cba70a9f7eac0723a2ce20551ba3ab6d4af0e8e095",
    "not_before": "2018-01-16T00:00:00.0000000Z",
    "not_after": "2021-03-16T23:59:59.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.3"
    ],
    "eku_codesigning": true,
    "self_signed": false,
    "crl_urls": [
      "http://tl.symcb.com/tl.crl"
    ],
    "ca_issuer_urls": [
      "http://tl.symcb.com/tl.crt"
    ],
    "ocsp_urls": [
      "http://tl.symcd.com"
    ]
  },
  "chain": {
    "chain_builds": false,
    "chains_to_trusted_root": true,
    "revoked": true,
    "explicit_distrust": false,
    "revocation_checked": "online",
    "valid_at_sign_time": false,
    "chain_length": 3,
    "chain": [
      {
        "subject": "CN=SimpleHelp Ltd, O=SimpleHelp Ltd, L=BURNTISLAND, C=GB",
        "subject_cn": "SimpleHelp Ltd",
        "issuer": "CN=thawte SHA256 Code Signing CA, O=\"thawte, Inc.\", C=US",
        "issuer_cn": "thawte SHA256 Code Signing CA",
        "serial_number": "51F83A8F29E96230568FBF2B05C27C77",
        "thumbprint": "0C1C560A51457A4D5BA378D389A9B0FF243BAE13",
        "md5_fingerprint": "1de867bf3b9205b591a8528503c7f4fc",
        "sha1_fingerprint": "0c1c560a51457a4d5ba378d389a9b0ff243bae13",
        "sha256_fingerprint": "8db44d50b25ba747234dfc8a4590a5790f331fb0022f61b0b660fa17b9bad752",
        "tbs_sha1": "acf2e617fe614c5e46194d58e774b9d01bcdaf15",
        "tbs_sha256": "a7e21bcb34e6eb3f36cb06cba70a9f7eac0723a2ce20551ba3ab6d4af0e8e095",
        "not_before": "2018-01-16T00:00:00.0000000Z",
        "not_after": "2021-03-16T23:59:59.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://tl.symcb.com/tl.crl"
        ],
        "ca_issuer_urls": [
          "http://tl.symcb.com/tl.crt"
        ],
        "ocsp_urls": [
          "http://tl.symcd.com"
        ]
      },
      {
        "subject": "CN=thawte SHA256 Code Signing CA, O=\"thawte, Inc.\", C=US",
        "subject_cn": "thawte SHA256 Code Signing CA",
        "issuer": "CN=thawte Primary Root CA, OU=\"(c) 2006 thawte, Inc. - For authorized use only\", OU=Certification Services Division, O=\"thawte, Inc.\", C=US",
        "issuer_cn": "thawte Primary Root CA",
        "serial_number": "71A0B73695DDB1AFC23B2B9A18EE54CB",
        "thumbprint": "D00CFDBF46C98A838BC10DC4E097AE0152C461BC",
        "md5_fingerprint": "871953a98d4150c33c69a0c5ae9a68c6",
        "sha1_fingerprint": "d00cfdbf46c98a838bc10dc4e097ae0152c461bc",
        "sha256_fingerprint": "c4d18e0a58e4effd17ed77c840b613ef15f551076ea92c2b77f6609a6c2557c7",
        "tbs_sha1": "b07dcf73133408eee2786a208ce4b2543bf6c583",
        "tbs_sha256": "c734685d985b8ea13db4fc1a6dcd26aa0dde78b4c3b651ea5d58e32e081b2a41",
        "not_before": "2013-12-10T00:00:00.0000000Z",
        "not_after": "2023-12-09T23:59:59.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.2",
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://t1.symcb.com/ThawtePCA.crl"
        ],
        "ca_issuer_urls": [],
        "ocsp_urls": [
          "http://t2.symcb.com"
        ]
      },
      {
        "subject": "CN=thawte Primary Root CA, OU=\"(c) 2006 thawte, Inc. - For authorized use only\", OU=Certification Services Division, O=\"thawte, Inc.\", C=US",
        "subject_cn": "thawte Primary Root CA",
        "issuer": "CN=thawte Primary Root CA, OU=\"(c) 2006 thawte, Inc. - For authorized use only\", OU=Certification Services Division, O=\"thawte, Inc.\", C=US",
        "issuer_cn": "thawte Primary Root CA",
        "serial_number": "344ED55720D5EDEC49F42FCE37DB2B6D",
        "thumbprint": "91C6D6EE3E8AC86384E548C299295C756C817B81",
        "md5_fingerprint": "8ccadc0b22cef5be72ac411a11a8d812",
        "sha1_fingerprint": "91c6d6ee3e8ac86384e548c299295c756c817b81",
        "sha256_fingerprint": "8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f",
        "tbs_sha1": "85fef11b4f47fe3952f98301c9f98976fefee0ce",
        "tbs_sha256": "b028b0b42913c43da25f0d80d23a9e4924e4db621af8a35cb20e5edff9e38b83",
        "not_before": "2006-11-17T00:00:00.0000000Z",
        "not_after": "2036-07-16T23:59:59.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "graveyard": {
    "hit": false
  },
  "timestamped": true,
  "sign_time": "2020-06-03T10:50:50.0000000Z",
  "sign_time_verified": true,
  "timestamper": {
    "subject": "CN=GlobalSign TSA for MS Authenticode - G2, O=GMO GlobalSign Pte Ltd, C=SG",
    "subject_cn": "GlobalSign TSA for MS Authenticode - G2",
    "issuer": "CN=GlobalSign Timestamping CA - G2, O=GlobalSign nv-sa, C=BE",
    "issuer_cn": "GlobalSign Timestamping CA - G2",
    "serial_number": "1121D699A764973EF1F8427EE919CC534114",
    "thumbprint": "63B82FAB61F583909695050B00249C502933EC79",
    "md5_fingerprint": "96a1a6678c3c59b9e99a297c3c65bc2b",
    "sha1_fingerprint": "63b82fab61f583909695050b00249c502933ec79",
    "sha256_fingerprint": "c38f3d9cca9492c1140487597c0c85edc7cc1294441c086cf496c11cbae664c0",
    "tbs_sha1": "bd6e261e75b807381bada7287de04d259258a5fa",
    "tbs_sha256": "4783380498acf592286ef2dea0fcc5bdea3f54d5e374d3e3497df9d5f662cfb6",
    "not_before": "2016-05-24T00:00:00.0000000Z",
    "not_after": "2027-06-24T00:00:00.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.8"
    ],
    "eku_codesigning": false,
    "self_signed": false,
    "crl_urls": [
      "http://crl.globalsign.com/gs/gstimestampingg2.crl"
    ],
    "ca_issuer_urls": [
      "http://secure.globalsign.com/cacert/gstimestampingg2.crt"
    ],
    "ocsp_urls": []
  },
  "ms": 1910
}
```
</details>

### MSI — [`Quadrantmediaed.msi`](https://bazaar.abuse.ch/sample/5da041b3f3efceaf8e49aee25177f1a9a1e2c1b869cf0d91de57fed8a8497c6a/) · revoked (ConnectWise)

A ConnectWise RMM installer signed with a DigiCert cert that was later revoked.

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file_sha256": "5da041b3f3efceaf8e49aee25177f1a9a1e2c1b869cf0d91de57fed8a8497c6a",
  "status": "Revoked",
  "signature_type": "Embedded",
  "content_verified": true,
  "is_os_binary": false,
  "signer": {
    "subject": "CN=\"ConnectWise, LLC\", O=\"ConnectWise, LLC\", L=Tampa, S=Florida, C=US",
    "subject_cn": "ConnectWise, LLC",
    "issuer": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=\"DigiCert, Inc.\", C=US",
    "issuer_cn": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    "serial_number": "0ABBCA120C79810A182F72F89C04358F",
    "thumbprint": "109D463C280A1E2AF6E87807C6F3D3E4A80E5DBE",
    "md5_fingerprint": "dcac21be66c5310ab798222b899c288c",
    "sha1_fingerprint": "109d463c280a1e2af6e87807c6f3d3e4a80e5dbe",
    "sha256_fingerprint": "b7902a93876909ba13bc23013f2c4239db57bfe742f500766a1673c5199fd1fb",
    "tbs_sha1": "e08a86e0feb4198ac05f799f516f16af0723174e",
    "tbs_sha256": "a9183c38f6658fe9ab270337c8905ca5458a1737abdd0b891aa9216605c307e7",
    "not_before": "2025-06-23T00:00:00.0000000Z",
    "not_after": "2028-06-22T23:59:59.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.3"
    ],
    "eku_codesigning": true,
    "self_signed": false,
    "crl_urls": [
      "http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl",
      "http://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl"
    ],
    "ca_issuer_urls": [
      "http://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt"
    ],
    "ocsp_urls": [
      "http://ocsp.digicert.com"
    ]
  },
  "chain": {
    "chain_builds": false,
    "chains_to_trusted_root": true,
    "revoked": true,
    "explicit_distrust": false,
    "revocation_checked": "online",
    "valid_at_sign_time": false,
    "chain_length": 3,
    "chain": [
      {
        "subject": "CN=\"ConnectWise, LLC\", O=\"ConnectWise, LLC\", L=Tampa, S=Florida, C=US",
        "subject_cn": "ConnectWise, LLC",
        "issuer": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=\"DigiCert, Inc.\", C=US",
        "issuer_cn": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "serial_number": "0ABBCA120C79810A182F72F89C04358F",
        "thumbprint": "109D463C280A1E2AF6E87807C6F3D3E4A80E5DBE",
        "md5_fingerprint": "dcac21be66c5310ab798222b899c288c",
        "sha1_fingerprint": "109d463c280a1e2af6e87807c6f3d3e4a80e5dbe",
        "sha256_fingerprint": "b7902a93876909ba13bc23013f2c4239db57bfe742f500766a1673c5199fd1fb",
        "tbs_sha1": "e08a86e0feb4198ac05f799f516f16af0723174e",
        "tbs_sha256": "a9183c38f6658fe9ab270337c8905ca5458a1737abdd0b891aa9216605c307e7",
        "not_before": "2025-06-23T00:00:00.0000000Z",
        "not_after": "2028-06-22T23:59:59.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl",
          "http://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl"
        ],
        "ca_issuer_urls": [
          "http://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt"
        ],
        "ocsp_urls": [
          "http://ocsp.digicert.com"
        ]
      },
      {
        "subject": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=\"DigiCert, Inc.\", C=US",
        "subject_cn": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "issuer": "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "issuer_cn": "DigiCert Trusted Root G4",
        "serial_number": "08AD40B260D29C4C9F5ECDA9BD93AED9",
        "thumbprint": "7B0F360B775F76C94A12CA48445AA2D2A875701C",
        "md5_fingerprint": "d91299e84355cd8d5a86795a0118b6e9",
        "sha1_fingerprint": "7b0f360b775f76c94a12ca48445aa2d2a875701c",
        "sha256_fingerprint": "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        "tbs_sha1": "79465b56bc7ad55a37bdf633943da8bfc84db228",
        "tbs_sha256": "84bdc82e2f2a7f7aaa782667dac556ffcb2b33240c1f9c0a00a3264526a98332",
        "not_before": "2021-04-29T00:00:00.0000000Z",
        "not_after": "2036-04-28T23:59:59.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://crl3.digicert.com/DigiCertTrustedRootG4.crl"
        ],
        "ca_issuer_urls": [
          "http://cacerts.digicert.com/DigiCertTrustedRootG4.crt"
        ],
        "ocsp_urls": [
          "http://ocsp.digicert.com"
        ]
      },
      {
        "subject": "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "subject_cn": "DigiCert Trusted Root G4",
        "issuer": "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "issuer_cn": "DigiCert Trusted Root G4",
        "serial_number": "059B1B579E8E2132E23907BDA777755C",
        "thumbprint": "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
        "md5_fingerprint": "78f2fcaa601f2fb4ebc937ba532e7549",
        "sha1_fingerprint": "ddfb16cd4931c973a2037d3fc83a4d7d775d05e4",
        "sha256_fingerprint": "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        "tbs_sha1": "420704040c93dfe9d3ad01a26c07f2be1f4888c1",
        "tbs_sha256": "4816e2e9e37ba61e1def6f7a4c623e981c7af355e51349b5554a3d56c5252e24",
        "not_before": "2013-08-01T12:00:00.0000000Z",
        "not_after": "2038-01-15T12:00:00.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "graveyard": {
    "hit": false
  },
  "timestamped": false,
  "sign_time": null,
  "sign_time_verified": false,
  "timestamper": null,
  "ms": 1236
}
```
</details>

### CAB — [`main1.cab`](https://bazaar.abuse.ch/sample/b4109feeaa85d8f4d67da8db0dc17054ffe28d285b7de6df46fb30e2d053a539/) · untrusted self-signed (ULTRAVNC)

The signer's subject *is* its issuer ("Photo and Fax viewer") — a self-signed cert with a deceptive name; the chain never reaches a trusted root, so `UntrustedRoot`.

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file_sha256": "b4109feeaa85d8f4d67da8db0dc17054ffe28d285b7de6df46fb30e2d053a539",
  "status": "UntrustedRoot",
  "signature_type": "Embedded",
  "content_verified": true,
  "is_os_binary": false,
  "signer": {
    "subject": "CN=Photo and Fax viewer",
    "subject_cn": "Photo and Fax viewer",
    "issuer": "CN=Photo and Fax viewer",
    "issuer_cn": "Photo and Fax viewer",
    "serial_number": "555F20A01D9D01924ED7387CEAC347B2",
    "thumbprint": "2E41F6894F8AA1F6DF63C6A025B3FC1BECE5B750",
    "md5_fingerprint": "52560f6e92c6394b102416b08883e8d5",
    "sha1_fingerprint": "2e41f6894f8aa1f6df63c6a025b3fc1bece5b750",
    "sha256_fingerprint": "677c54f470101e83033e017e9f60bbf1b0f9a813cdf6b7bbaadc2bb1888bd415",
    "tbs_sha1": "fee65b77441409137f5af7ae14539c9b3d9f8b3a",
    "tbs_sha256": "949335586a6b75a3fca37d9e3c779fb4a767efbf5c9dad2291c24224ec88a680",
    "not_before": "2021-11-23T08:44:29.0000000Z",
    "not_after": "2022-11-23T09:04:29.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.3"
    ],
    "eku_codesigning": true,
    "self_signed": true,
    "crl_urls": [],
    "ca_issuer_urls": [],
    "ocsp_urls": []
  },
  "chain": {
    "chain_builds": false,
    "chains_to_trusted_root": false,
    "revoked": false,
    "explicit_distrust": false,
    "revocation_checked": "online",
    "valid_at_sign_time": false,
    "chain_length": 1,
    "chain": [
      {
        "subject": "CN=Photo and Fax viewer",
        "subject_cn": "Photo and Fax viewer",
        "issuer": "CN=Photo and Fax viewer",
        "issuer_cn": "Photo and Fax viewer",
        "serial_number": "555F20A01D9D01924ED7387CEAC347B2",
        "thumbprint": "2E41F6894F8AA1F6DF63C6A025B3FC1BECE5B750",
        "md5_fingerprint": "52560f6e92c6394b102416b08883e8d5",
        "sha1_fingerprint": "2e41f6894f8aa1f6df63c6a025b3fc1bece5b750",
        "sha256_fingerprint": "677c54f470101e83033e017e9f60bbf1b0f9a813cdf6b7bbaadc2bb1888bd415",
        "tbs_sha1": "fee65b77441409137f5af7ae14539c9b3d9f8b3a",
        "tbs_sha256": "949335586a6b75a3fca37d9e3c779fb4a767efbf5c9dad2291c24224ec88a680",
        "not_before": "2021-11-23T08:44:29.0000000Z",
        "not_after": "2022-11-23T09:04:29.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": true,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "graveyard": {
    "hit": false
  },
  "timestamped": true,
  "sign_time": "2023-03-01T10:18:26.0000000Z",
  "sign_time_verified": true,
  "timestamper": {
    "subject": "CN=DigiCert Timestamp 2022 - 2, O=DigiCert, C=US",
    "subject_cn": "DigiCert Timestamp 2022 - 2",
    "issuer": "CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA, O=\"DigiCert, Inc.\", C=US",
    "issuer_cn": "DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",
    "serial_number": "0C4D69724B94FA3C2A4A3D2907803D5A",
    "thumbprint": "F387224D8633829235A994BCBD8F96E9FE1C7C73",
    "md5_fingerprint": "c1b349871880f9359e1e241630313de9",
    "sha1_fingerprint": "f387224d8633829235a994bcbd8f96e9fe1c7c73",
    "sha256_fingerprint": "c7f4e1be32288920abe2263abe1ac4fc4fe6781c2d64d04c807557a023b5b6fa",
    "tbs_sha1": "3f8047d078307123301e50a25e9afb0dc4b6843d",
    "tbs_sha256": "0c0b121e6f807bc22d4e0f4945634c22eca7e4d5ca58a1526a40e918a35c1d79",
    "not_before": "2022-09-21T00:00:00.0000000Z",
    "not_after": "2033-11-21T23:59:59.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.8"
    ],
    "eku_codesigning": false,
    "self_signed": false,
    "crl_urls": [
      "http://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl"
    ],
    "ca_issuer_urls": [
      "http://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt"
    ],
    "ocsp_urls": [
      "http://ocsp.digicert.com"
    ]
  },
  "ms": 303
}
```
</details>

### Script (`.js`) — [`out_bdrts.js`](https://bazaar.abuse.ch/sample/fad25892e5179a346cdbdbba1e40f53bd6366806d32b57fa4d7946ebe9ae8621/) · valid signature, malicious file (GuLoader)

The signature is genuinely valid — a real GlobalSign **EV** code-signing cert — yet the file is GuLoader. **A valid signature is not a safety verdict.** For scripts myatg takes `status` from `Get-AuthenticodeSignature` (OS truth) and adds the native signer/timestamp metadata.

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file_sha256": "fad25892e5179a346cdbdbba1e40f53bd6366806d32b57fa4d7946ebe9ae8621",
  "status": "Valid",
  "signature_type": "Script",
  "content_verified": true,
  "is_os_binary": false,
  "signer": {
    "subject": "CN=TAIM LLC, O=TAIM LLC, STREET=\"Vavilov street, 4 pom 13N\", L=Moscow, S=Moscow, C=RU, OID.1.3.6.1.4.1.311.60.2.1.2=Moscow, OID.1.3.6.1.4.1.311.60.2.1.3=RU, SERIALNUMBER=1237700338303, OID.2.5.4.15=Private Organization",
    "subject_cn": "TAIM LLC",
    "issuer": "CN=GlobalSign GCC R45 EV CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE",
    "issuer_cn": "GlobalSign GCC R45 EV CodeSigning CA 2020",
    "serial_number": "4484F1C5B6A72DFEC0E1CA55",
    "thumbprint": "4CB87577FA5B91346CCE30FB9FF3139D46DE3361",
    "md5_fingerprint": "0cd8a255094ca744923d91a67caec729",
    "sha1_fingerprint": "4cb87577fa5b91346cce30fb9ff3139d46de3361",
    "sha256_fingerprint": "f418f16e61222714a46cff8ec9cdd3a5dec716808dadc876581ee353ed2b339c",
    "tbs_sha1": "ef5e878e3c896f63da1cb24c2bb91e53b441a52f",
    "tbs_sha256": "88d9a5a1a91ddc74da85e8279008b1b118a5fc246f7059cd1cf6f3052b573b6d",
    "not_before": "2023-06-13T07:18:04.0000000Z",
    "not_after": "2024-06-13T07:18:04.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.3"
    ],
    "eku_codesigning": true,
    "self_signed": false,
    "crl_urls": [
      "http://crl.globalsign.com/gsgccr45evcodesignca2020.crl"
    ],
    "ca_issuer_urls": [
      "http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt"
    ],
    "ocsp_urls": [
      "http://ocsp.globalsign.com/gsgccr45evcodesignca2020"
    ]
  },
  "chain": {
    "chain_builds": true,
    "chains_to_trusted_root": true,
    "revoked": false,
    "explicit_distrust": false,
    "revocation_checked": "online",
    "valid_at_sign_time": true,
    "chain_length": 3,
    "chain": [
      {
        "subject": "CN=TAIM LLC, O=TAIM LLC, STREET=\"Vavilov street, 4 pom 13N\", L=Moscow, S=Moscow, C=RU, OID.1.3.6.1.4.1.311.60.2.1.2=Moscow, OID.1.3.6.1.4.1.311.60.2.1.3=RU, SERIALNUMBER=1237700338303, OID.2.5.4.15=Private Organization",
        "subject_cn": "TAIM LLC",
        "issuer": "CN=GlobalSign GCC R45 EV CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE",
        "issuer_cn": "GlobalSign GCC R45 EV CodeSigning CA 2020",
        "serial_number": "4484F1C5B6A72DFEC0E1CA55",
        "thumbprint": "4CB87577FA5B91346CCE30FB9FF3139D46DE3361",
        "md5_fingerprint": "0cd8a255094ca744923d91a67caec729",
        "sha1_fingerprint": "4cb87577fa5b91346cce30fb9ff3139d46de3361",
        "sha256_fingerprint": "f418f16e61222714a46cff8ec9cdd3a5dec716808dadc876581ee353ed2b339c",
        "tbs_sha1": "ef5e878e3c896f63da1cb24c2bb91e53b441a52f",
        "tbs_sha256": "88d9a5a1a91ddc74da85e8279008b1b118a5fc246f7059cd1cf6f3052b573b6d",
        "not_before": "2023-06-13T07:18:04.0000000Z",
        "not_after": "2024-06-13T07:18:04.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://crl.globalsign.com/gsgccr45evcodesignca2020.crl"
        ],
        "ca_issuer_urls": [
          "http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt"
        ],
        "ocsp_urls": [
          "http://ocsp.globalsign.com/gsgccr45evcodesignca2020"
        ]
      },
      {
        "subject": "CN=GlobalSign GCC R45 EV CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE",
        "subject_cn": "GlobalSign GCC R45 EV CodeSigning CA 2020",
        "issuer": "CN=GlobalSign Code Signing Root R45, O=GlobalSign nv-sa, C=BE",
        "issuer_cn": "GlobalSign Code Signing Root R45",
        "serial_number": "77BD0E05B7590BB61D4761531E3F75ED",
        "thumbprint": "C10BB76AD4EE815242406A1E3E1117FFEC743D4F",
        "md5_fingerprint": "e6eb41ad6404317af8a18b64f98c2bcf",
        "sha1_fingerprint": "c10bb76ad4ee815242406a1e3e1117ffec743d4f",
        "sha256_fingerprint": "cd0e144dd10bac221fe2fb901058d16450a0578b3c47c770908f2e9ada28ef12",
        "tbs_sha1": "c7cf5607e19b22fe60c055e71d9b555d70f71f66",
        "tbs_sha256": "d9c7db0b704f07089440c56e69a0f31d730edf77cfbf7514630e8b5390a270fe",
        "not_before": "2020-07-28T00:00:00.0000000Z",
        "not_after": "2030-07-28T00:00:00.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.3"
        ],
        "eku_codesigning": true,
        "self_signed": false,
        "crl_urls": [
          "http://crl.globalsign.com/codesigningrootr45.crl"
        ],
        "ca_issuer_urls": [
          "http://secure.globalsign.com/cacert/codesigningrootr45.crt"
        ],
        "ocsp_urls": [
          "http://ocsp.globalsign.com/codesigningrootr45"
        ]
      },
      {
        "subject": "CN=GlobalSign Code Signing Root R45, O=GlobalSign nv-sa, C=BE",
        "subject_cn": "GlobalSign Code Signing Root R45",
        "issuer": "CN=GlobalSign Code Signing Root R45, O=GlobalSign nv-sa, C=BE",
        "issuer_cn": "GlobalSign Code Signing Root R45",
        "serial_number": "7653FEAC75464893F5E5D74A483A4EF8",
        "thumbprint": "4EFC31460C619ECAE59C1BCE2C008036D94C84B8",
        "md5_fingerprint": "e94fb54871208c00df70f708ac47085b",
        "sha1_fingerprint": "4efc31460c619ecae59c1bce2c008036d94c84b8",
        "sha256_fingerprint": "7b9d553e1c92cb6e8803e137f4f287d4363757f5d44b37d52f9fca22fb97df86",
        "tbs_sha1": "bf5b5b0d5e2d7da7f29d1c6f506bf58a8228b6fb",
        "tbs_sha256": "b5a2853291077af152474fc478d13c166c4d4f60b6aeb869ff24275310cf1c67",
        "not_before": "2020-03-18T00:00:00.0000000Z",
        "not_after": "2045-03-18T00:00:00.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "graveyard": {
    "hit": true,
    "matched_on": "cert_tbs_sha256",
    "malware": "FlawedAmmyy",
    "malware_type": ""
  },
  "timestamped": true,
  "sign_time": "2024-04-04T14:42:51.0000000Z",
  "sign_time_verified": true,
  "timestamper": {
    "subject": "CN=DigiCert Timestamp 2023, O=\"DigiCert, Inc.\", C=US",
    "subject_cn": "DigiCert Timestamp 2023",
    "issuer": "CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA, O=\"DigiCert, Inc.\", C=US",
    "issuer_cn": "DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",
    "serial_number": "0544AFF3949D0839A6BFDB3F5FE56116",
    "thumbprint": "66F02B32C2C2C90F825DCEAA8AC9C64F199CCF40",
    "md5_fingerprint": "a6ba5fdf34f4060a647083be314f6f24",
    "sha1_fingerprint": "66f02b32c2c2c90f825dceaa8ac9c64f199ccf40",
    "sha256_fingerprint": "d2f6e46ded7422ccd1d440576841366f828ada559aae3316af4d1a9ad40c7828",
    "tbs_sha1": "bc1890d694f9d392c4cbae6a174e35d70e7ec8b1",
    "tbs_sha256": "594a02de632b3a08ed6644c36994025e57f35bc8e7bd16cec5d347883390d1d8",
    "not_before": "2023-07-14T00:00:00.0000000Z",
    "not_after": "2034-10-13T23:59:59.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.8"
    ],
    "eku_codesigning": false,
    "self_signed": false,
    "crl_urls": [
      "http://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl"
    ],
    "ca_issuer_urls": [
      "http://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt"
    ],
    "ocsp_urls": [
      "http://ocsp.digicert.com"
    ]
  },
  "ms": 2520
}
```
</details>

### RDP — [`ukrtelecom.eu.rdp`](https://bazaar.abuse.ch/sample/1916af4debbeaa0ee688c95d2d9d25196bd5765bad5c7a9c1ed7e934e6ffb9ba/) · expired, TLS-cert misuse (APT29 lure)

A typosquatted domain, signed with a Let's Encrypt **TLS** cert — note the EKU (`serverAuth`/`clientAuth`, *not* code-signing) — that has since expired. myatg crypto-verifies the `rdpsign` content, validates the chain, and reports **signscope coverage** + any present-but-unsigned high-risk settings (`unsigned_dangerous`).

<details>
<summary>Full <code>myatg.exe</code> JSON</summary>

```json
{
  "file": "f01392.rdp",
  "status": "Expired",
  "signature_type": "RDP",
  "signer": {
    "subject": "CN=ukrtelecom.eu",
    "subject_cn": "ukrtelecom.eu",
    "issuer": "CN=R10, O=Let's Encrypt, C=US",
    "issuer_cn": "R10",
    "serial_number": "03D51E1A3713698BB3F471068072916E8F2D",
    "thumbprint": "37575F848570005D12C59135225784C1AE2DC295",
    "md5_fingerprint": "8562ec2edca46141a5bd1d7bd89912f0",
    "sha1_fingerprint": "37575f848570005d12c59135225784c1ae2dc295",
    "sha256_fingerprint": "1f1218b9bc005cbb67fe856b8400241703b64080018ad989998275bd9c7f86d0",
    "tbs_sha1": "68eca3eb30a472d14c22cb0a7121429e0f79b968",
    "tbs_sha256": "b5c13e69271d3e7fc2b95bf098c70fa9bff3311735329cad7f9dac14df919cf7",
    "not_before": "2025-01-22T06:49:47.0000000Z",
    "not_after": "2025-04-22T06:49:46.0000000Z",
    "eku": [
      "1.3.6.1.5.5.7.3.1",
      "1.3.6.1.5.5.7.3.2"
    ],
    "eku_codesigning": false,
    "self_signed": false,
    "crl_urls": [],
    "ca_issuer_urls": [
      "http://r10.i.lencr.org/"
    ],
    "ocsp_urls": [
      "http://r10.o.lencr.org"
    ]
  },
  "chain": {
    "signature_valid": true,
    "chains_to_trusted_root": true,
    "revoked": false,
    "explicit_distrust": false,
    "revocation_checked": "unknown",
    "not_before": "2025-01-22T06:49:47.0000000Z",
    "not_after": "2025-04-22T06:49:46.0000000Z",
    "expired_now": true,
    "not_yet_valid": false,
    "valid_now": false,
    "sign_time": null,
    "sign_time_verified": false,
    "valid_at_sign_time": false,
    "chain_length": 3,
    "chain": [
      {
        "subject": "CN=ukrtelecom.eu",
        "subject_cn": "ukrtelecom.eu",
        "issuer": "CN=R10, O=Let's Encrypt, C=US",
        "issuer_cn": "R10",
        "serial_number": "03D51E1A3713698BB3F471068072916E8F2D",
        "thumbprint": "37575F848570005D12C59135225784C1AE2DC295",
        "md5_fingerprint": "8562ec2edca46141a5bd1d7bd89912f0",
        "sha1_fingerprint": "37575f848570005d12c59135225784c1ae2dc295",
        "sha256_fingerprint": "1f1218b9bc005cbb67fe856b8400241703b64080018ad989998275bd9c7f86d0",
        "tbs_sha1": "68eca3eb30a472d14c22cb0a7121429e0f79b968",
        "tbs_sha256": "b5c13e69271d3e7fc2b95bf098c70fa9bff3311735329cad7f9dac14df919cf7",
        "not_before": "2025-01-22T06:49:47.0000000Z",
        "not_after": "2025-04-22T06:49:46.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.1",
          "1.3.6.1.5.5.7.3.2"
        ],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [
          "http://r10.i.lencr.org/"
        ],
        "ocsp_urls": [
          "http://r10.o.lencr.org"
        ]
      },
      {
        "subject": "CN=R10, O=Let's Encrypt, C=US",
        "subject_cn": "R10",
        "issuer": "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
        "issuer_cn": "ISRG Root X1",
        "serial_number": "4BA85293F79A2FA273064BA8048D75D0",
        "thumbprint": "00ABEFD055F9A9C784FFDEABD1DCDD8FED741436",
        "md5_fingerprint": "af1c77aecc8d77e9aacb0c475840c392",
        "sha1_fingerprint": "00abefd055f9a9c784ffdeabd1dcdd8fed741436",
        "sha256_fingerprint": "9d7c3f1aa6ad2b2ec0d5cf1e246f8d9ae6cbc9fd0755ad37bb974b1f2fb603f3",
        "tbs_sha1": "fbd00d8384012755bc869b5d96aadc2182176a9f",
        "tbs_sha256": "e644ba6963e335fe765cb9976b12b10eb54294b42477764ccb3a3acca3acb2fc",
        "not_before": "2024-03-13T00:00:00.0000000Z",
        "not_after": "2027-03-12T23:59:59.0000000Z",
        "eku": [
          "1.3.6.1.5.5.7.3.2",
          "1.3.6.1.5.5.7.3.1"
        ],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [
          "http://x1.c.lencr.org/"
        ],
        "ca_issuer_urls": [
          "http://x1.i.lencr.org/"
        ],
        "ocsp_urls": []
      },
      {
        "subject": "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
        "subject_cn": "ISRG Root X1",
        "issuer": "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
        "issuer_cn": "ISRG Root X1",
        "serial_number": "008210CFB0D240E3594463E0BB63828B00",
        "thumbprint": "CABD2A79A1076A31F21D253635CB039D4329A5E8",
        "md5_fingerprint": "0cd2f9e0da1773e9ed864da5e370e74e",
        "sha1_fingerprint": "cabd2a79a1076a31f21d253635cb039d4329a5e8",
        "sha256_fingerprint": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
        "tbs_sha1": "8d5fb83aa3e5c68fa6cfcdc6489a5735ba7ad4f0",
        "tbs_sha256": "3f0411ede9c4477057d57e57883b1f205b20cdc0f3263129b1ee0269a2678f63",
        "not_before": "2015-06-04T11:04:38.0000000Z",
        "not_after": "2035-06-04T11:04:38.0000000Z",
        "eku": [],
        "eku_codesigning": false,
        "self_signed": false,
        "crl_urls": [],
        "ca_issuer_urls": [],
        "ocsp_urls": []
      }
    ]
  },
  "signscope_count": 26,
  "total_settings": 51,
  "unsigned_settings": 25,
  "unsigned_dangerous": []
}
```
</details>


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
