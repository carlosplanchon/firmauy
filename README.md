# FirmaUY

![FirmaUY banner](https://raw.githubusercontent.com/carlosplanchon/firmauy/main/assets/banner_firmauy.jpg)

Sign and verify PDF (PAdES), XML (XAdES) and arbitrary files (CAdES/.p7s) locally using a Uruguayan national ID card (cédula) through PKCS#11. Standards-based signatures that verify with standard validators, with local chain validation to the Uruguayan national root.

[![PyPI version](https://img.shields.io/pypi/v/firmauy.svg)](https://pypi.org/project/firmauy/)
[![Python versions](https://img.shields.io/pypi/pyversions/firmauy.svg)](https://pypi.org/project/firmauy/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/firmauy)

> ⚠️ **Disclaimer**: This tool performs **local, technical** signing and verification using open standards. It is experimental, community-maintained, **not affiliated with AGESIC**, **not officially certified**, and **does not guarantee legal validity**. For official validation, use the [official AGESIC validator](https://firma.gub.uy/); see [Legal and compliance](#legal-and-compliance) for details.

## Quick start

> Requires **Linux** with the Uruguayan cédula PKCS#11 middleware installed. The full smart-card setup is in [Requirements](#requirements) and [Setup on Arch Linux](#setup-on-arch-linux).

```bash
uv tool install firmauy                # install
firmauy doctor                         # check the setup (pcscd, PKCS#11 module, card, CAs)
firmauy list-tokens                    # confirm the card is detected
firmauy sign-pdf input.pdf             # sign -> input_firmado.pdf (prompts for the PIN)
firmauy verify input_firmado.pdf       # verify (auto-detects format; offline chain check)
```

## Overview

FirmaUY provides a local, developer-oriented workflow for **signing and verifying** documents and files with a Uruguayan national ID card (cédula) using PKCS#11 middleware: PDF (PAdES), XML (XAdES) and detached CAdES/.p7s signatures for arbitrary files.

The CLI tool is invoked as `firmauy` and supports:

- signing individual PDF documents
- batch-signing multiple PDFs with a single PKCS#11 session
- signing XML documents, individually or in batch (XAdES-BES, or XAdES-T with `--tsa-url`; enveloped)
- signing arbitrary files, individually or in batch (CAdES-BES detached `.p7s`, CMS/PKCS#7)
- verifying signed PDF, XML and detached `.p7s` files locally, with chain validation to the national root
- configuring the visible signature position
- selecting the signature page
- discovering PC/SC readers, PKCS#11 tokens and certificates
- reading the cardholder's biographical data and photo from the card, without a PIN (`fetch-identity` / `fetch-photo`)
- validating a cédula number's check digit offline, with no card or PIN (`validate-ci`)
- diagnosing the local setup with `doctor`
- non-interactive PIN sources for controlled automation workflows

## Supported signature formats

| Format | Command | Output | Verification | Timestamping |
|---|---|---|---|---|
| PDF / PAdES | `sign-pdf` | signed `.pdf` | `verify-pdf` / `verify` | optional (external TSA) |
| XML / XAdES | `sign-xml` | signed `.xml` | `verify-xml` / `verify` | optional (external TSA) |
| Any file / CAdES | `sign-any` | detached `.p7s` | `verify-any` / `verify` | optional (external TSA) |

The full AdES triad (PAdES / XAdES / CAdES), signed locally with the cédula and verifiable with
standard validators; local verification anchors the chain to the Uruguayan national root. Each
command has a batch variant (`sign-pdf-batch`, `sign-xml-batch`, `sign-any-batch`).

Timestamping is **optional and bring-your-own**: it works with any external RFC 3161 TSA via
`--tsa-url`, but it is **not** part of the standard cédula flow, and Uruguay has no free public TSA
(the accredited qualified ones are gated). See [Timestamping](#timestamping-tsa-optional).

## Requirements

### Hardware

- Smart card reader compatible with your OS
- Uruguayan ID card (cédula) with active certificate

### Operating system

This tool targets **Linux** and is primarily developed and tested on **Arch Linux**.

Other Linux distributions may work if the required smart card stack, PKCS#11 middleware, and Python environment are correctly configured.

**Windows and macOS are not currently supported or tested.**

### Python

Python **3.10 or newer**.

### PKCS#11 middleware

The default PKCS#11 module expected by this tool is:

```text
/usr/lib/pkcs11/libgclib.so
```

On Arch Linux, this is provided by the `cedula-uruguay-pkcs11` AUR package.

## Setup on Arch Linux

### 1. Install smart card stack

```bash
sudo pacman -S pcsclite ccid pcsc-tools opensc
sudo systemctl enable --now pcscd
```

### 2. Install PKCS#11 library for the Uruguayan ID card

Install the PKCS#11 module from AUR:

```bash
yay -S cedula-uruguay-pkcs11
# or manually:
# https://aur.archlinux.org/packages/cedula-uruguay-pkcs11
```

This is a **community-maintained** AUR package that repackages the official cédula drivers distributed by the Uruguayan government. It is not an official government package.

It provides the default PKCS#11 module used by this tool:

```text
/usr/lib/pkcs11/libgclib.so
```

Use version `7.5.0-2` or later; older versions could crash the process when a wrong PIN was entered.

## Installation

### Installation with uv

```bash
uv tool install firmauy
```

## Usage

The CLI tool is invoked as `firmauy`.

For task-oriented, copy-pasteable recipes (sign and verify, privacy/debug, automation, `jq`
pipelines), see the **[cookbook](docs/cookbook.md)**.

### CLI help

Use `--help` on any command to see all available options:

```bash
firmauy --version            # print the installed version
firmauy --help
firmauy sign-pdf --help
firmauy sign-pdf-batch --help
```

### Sign a single PDF

```bash
firmauy sign-pdf input.pdf output_signed.pdf
```

The tool will prompt for the PKCS#11 PIN interactively.

If the output path is omitted, the signed file is saved as:

```text
<input>_firmado.pdf
```

### Signing sanity check (`--verify`) vs full verification

These are two different things, and the distinction matters:

- **`sign-pdf --verify`** (also `sign-xml` / `sign-any` and their `*-batch` variants): an immediate
  **sanity check** of the signature just produced, right after writing it (integrity, and for PDFs
  full-file coverage). It does **not** validate the trust chain; it catches a corrupt or malformed
  output on the spot. If the signature is not intact the command fails (non-zero exit); in batch it
  counts as an error for that file.
- **`verify-pdf` / `verify-xml` / `verify-any` / `verify`**: a full **technical verification**,
  including the certificate chain to the Uruguayan national root (see below).

```bash
firmauy sign-pdf input.pdf --verify
# PDF signed successfully: input_firmado.pdf
# Verified: signature intact and covers the whole file.
```

### Custom signature position

```bash
firmauy sign-pdf input.pdf output_signed.pdf --x1 20 --y1 20 --x2 225 --y2 90
```

### Image in the signature appearance

You can add an image (PNG/JPEG) to the visible signature, e.g. a handwritten signature or an
institutional seal/logo. This is **cosmetic only**: it does not change the cryptographic
signature or its validity.

```bash
firmauy sign-pdf input.pdf --image firma.png                       # default: behind the text
firmauy sign-pdf input.pdf --image firma.png --image-mode side     # left of the text
firmauy sign-pdf input.pdf --image firma.png --image-mode only     # image, no text
```

`--image-mode` controls the layout inside the signature box:

- `background` (default): the image sits behind the text as a subtle watermark. The signature
  text (signer, document, date, issuer) stays fully readable. Tune with `--image-opacity 0..1`
  (default `0.2`).
- `side`: the image goes to the left, the text reflows into the narrower right column.
- `only`: just the image, no text (e.g. a scanned handwritten signature).

PNG transparency is supported. The image is scaled to fit the signature box, preserving its
aspect ratio. `--image` is also available on `sign-pdf-batch`.

### Specify page

Pages are 0-indexed. Use `-1` to sign the last page.

```bash
firmauy sign-pdf input.pdf output_signed.pdf --page 0
```

### Non-interactive PIN

PIN can be supplied without an interactive prompt via `--pin-source`:

```bash
# From an environment variable
firmauy sign-pdf input.pdf output_signed.pdf --pin-source env --pin-env-var MY_PIN

# From stdin
echo "1234" | firmauy sign-pdf input.pdf output_signed.pdf --pin-source stdin

# From a file descriptor
firmauy sign-pdf input.pdf output_signed.pdf --pin-source fd --pin-fd 3
```

Choose the source by security context (most to least contained):

| Source | Use for | Why |
| --- | --- | --- |
| `prompt` | manual use | the PIN is only typed; never on disk, argv or env |
| `fd` | secure automation | a dedicated file descriptor you control; not in argv or env |
| `stdin` | controlled automation | not in argv, but a literal `echo "$PIN" \|` can leak to shell history or process lists |
| `env` | closed/isolated environments only | last resort: environment variables are inherited by child processes, readable via `/proc/<pid>/environ` and `ps eww`, and can surface in core dumps, container inspection and CI logs |

⚠️ However the PIN is supplied, avoid having it appear in shell history, process lists or logs.

### Timestamping (TSA, optional)

Embed a trusted timestamp from a Time Stamping Authority (RFC 3161), available on every signing command (`sign-pdf`, `sign-xml`, `sign-any` and their `*-batch` variants), producing the **-T** level (PAdES-T / XAdES-T / CAdES-T):

```bash
firmauy sign-pdf input.pdf output_signed.pdf --tsa-url https://your-tsa/endpoint
firmauy sign-xml document.xml --tsa-url https://your-tsa/endpoint   # XAdES-T
firmauy sign-any contract.zip --tsa-url https://your-tsa/endpoint   # CAdES-T
```

**Credentialed TSAs.** For a TSA that requires authentication, firmauy supports HTTP Basic auth and arbitrary headers. Secrets (the Basic-auth password, a Bearer token / API key) are read from environment variables, never taken on the command line where they would be visible in the process list (`ps` / `/proc`):

```bash
# HTTP Basic auth (password from an env var)
TSA_PW='secret' firmauy sign-any contract.zip \
  --tsa-url https://your-tsa/endpoint --tsa-user alice --tsa-pass-env TSA_PW

# Bearer token / API key via a header whose value is read from an env var (kept off argv)
TSA_TOKEN="Bearer $TOKEN" firmauy sign-any contract.zip --tsa-url https://your-tsa/endpoint \
  --tsa-header-env "Authorization: TSA_TOKEN"

# Non-secret headers can be passed literally
firmauy sign-any contract.zip --tsa-url https://your-tsa/endpoint \
  --tsa-header "X-Trace-Id: abc123"
```

TSA timestamping is **optional** and **not required** for the standard Uruguayan cédula flow (the official tools sign at the BES level, without a timestamp). It is **bring-your-own**: any external RFC 3161 TSA works. Uruguay has no free public TSA, and the accredited *qualified* timestamping services (e.g. Antel/TuID, regulated by the UCE) are gated behind subscriber credentials. So a *qualified* Uruguayan timestamp requires access you arrange separately, while any public RFC 3161 TSA still gives a technical timestamp. A timestamp adds trusted-time evidence and involves an external network request to the TSA.

> Any public RFC 3161 TSA works here for a **technical** timestamp; a *qualified* timestamp requires credentials from an accredited provider (which is what `--tsa-user` / `--tsa-header` / `--tsa-header-env` are for). Client-certificate (mTLS) TSAs are **not** supported.

### Sign batch

Sign multiple PDFs with a single PKCS#11 session. The card PIN is entered only once.

```bash
# Explicit file list
firmauy sign-pdf-batch file1.pdf file2.pdf file3.pdf --output-dir ~/signed

# Whole directory
firmauy sign-pdf-batch --input-dir ~/docs --output-dir ~/signed

# Whole directory, recursively
firmauy sign-pdf-batch --input-dir ~/docs --recursive --output-dir ~/signed

# Both can be combined
firmauy sign-pdf-batch extra.pdf --input-dir ~/docs --output-dir ~/signed
```

Output files are named `<original-name>_firmado.pdf` by default.

Change the suffix with `--suffix`:

```bash
firmauy sign-pdf-batch --input-dir ~/docs --output-dir ~/signed --suffix _signed
```

The output directory is created automatically if it does not exist.

All options available for `sign-pdf` (position, PIN source, reason, TSA, etc.) are also available for `sign-pdf-batch`.

⚠️ This tool produces cryptographic signatures. Legal validity depends on applicable regulations and use context.

Make sure you have reviewed all documents before signing them in batch.

### Sign an XML document (XAdES)

Sign an XML document with the cédula, producing a standards-based **XAdES-BES enveloped**
signature following the XAdES specification (ETSI EN 319 132). The signatures verify with
independent XAdES validators (the test suite cross-checks against `signxml`), so they suit signing
generic structured XML documents.

```bash
firmauy sign-xml input.xml output_signed.xml
```

If the output path is omitted, the signed file is saved as `<input>_firmado.xml`.

Token discovery, certificate selection and PIN handling work exactly like the PDF commands, so
the same options apply: `--token-label`, `--cert-id`, `--pin-source` (with `--pin-env-var` /
`--pin-fd`), `--timezone`, `--tsa-url` (adds an XAdES-T timestamp, see
[Timestamping](#timestamping-tsa-optional)) and `--overwrite`.

```bash
# Non-interactive PIN, same as the PDF commands
echo "1234" | firmauy sign-xml input.xml output_signed.xml --pin-source stdin
```

Signature profile produced:

- **Format:** XAdES-BES (or XAdES-T with `--tsa-url`), enveloped; the `<ds:Signature>` is appended
  as the last child of the document root, with a single reference over the whole document (`URI=""`).
- **Canonicalization:** inclusive C14N 1.0 (`REC-xml-c14n-20010315`).
- **Algorithms:** RSA-SHA256 signature, SHA-256 digests.
- **Signed properties:** signing time, signing-certificate digest and data-object format.

⚠️ This is the XAdES-**BES** level (no trusted timestamp). The produced signature is
cryptographically valid and conforms to the XAdES standard; legal and regulatory validity
depends on your use case and applicable rules.

### Sign multiple XML documents (batch)

Sign many XML files with a single PKCS#11 session (the card PIN is entered only once). This
mirrors `sign-pdf-batch` for PDFs and is convenient for bulk signing workflows.

```bash
# Explicit file list
firmauy sign-xml-batch file1.xml file2.xml --output-dir ~/signed

# Whole directory (add --recursive to descend into subfolders)
firmauy sign-xml-batch --input-dir ~/docs --output-dir ~/signed
```

For unattended bulk signing, supply the PIN non-interactively (entered once for the whole
batch), exactly as with the other commands:

```bash
# PIN from an environment variable
firmauy sign-xml-batch --input-dir ~/docs --output-dir ~/signed \
  --pin-source env --pin-env-var MY_PIN

# PIN from stdin
echo "1234" | firmauy sign-xml-batch --input-dir ~/docs --output-dir ~/signed --pin-source stdin
```

Output files are named `<original-name>_firmado.xml` by default; change it with `--suffix`. The
output directory is created automatically. All the `sign-xml` options (token, certificate and
PIN selection, `--timezone`, `--overwrite`) also apply.

Make sure you have reviewed all documents before signing them in batch.

### Sign any file (detached CAdES / .p7s)

Sign **any file** (not just PDF or XML) with the cédula, producing a standards-based
**CAdES-BES detached** signature (RFC 5652 CMS / PKCS#7), following ETSI EN 319 122. This
completes the AdES triad alongside PAdES (PDF) and XAdES (XML).

```bash
firmauy sign-any contract.zip
```

The signature is **detached**: the original file is left untouched and the signature is written
to a separate `.p7s`. If the output path is omitted, it is saved next to the input as
`<input-name>.p7s` (e.g. `contract.zip` → `contract.zip.p7s`).

Token discovery, certificate selection and PIN handling work exactly like the PDF/XML commands,
so the same options apply: `--token-label`, `--cert-id`, `--pin-source` (with `--pin-env-var` /
`--pin-fd`), `--tsa-url` and `--overwrite`.

```bash
# Non-interactive PIN, same as the other commands
echo "1234" | firmauy sign-any contract.zip --pin-source stdin
```

Signature profile produced:

- **Format:** CAdES-BES, detached (RFC 5652 CMS / PKCS#7); the original bytes are not embedded.
- **Algorithms:** RSA-SHA256 signature, SHA-256 message digest.
- **Signed attributes:** content type, message digest and `signing-certificate-v2` (the CMS
  counterpart of the XAdES SigningCertificate).

It verifies with standard CMS tooling, e.g. `openssl cms -verify -binary -inform DER -in
contract.zip.p7s -content contract.zip`, or with `firmauy verify-any` (see below).

⚠️ This is the CAdES-**BES** level (no trusted timestamp). Passing `--tsa-url` embeds a trusted
timestamp (CAdES-T), at the cost of contacting that external TSA. The produced signature is
cryptographically valid and conforms to the CMS/CAdES standard; legal and regulatory validity
depends on your use case and applicable rules.

### Sign multiple files (batch)

Sign many files with a single PKCS#11 session (the card PIN is entered only once), mirroring the
PDF and XML batch commands.

```bash
# Explicit file list
firmauy sign-any-batch a.zip b.bin report.docx --output-dir ~/signed

# Whole directory (add --recursive to descend into subfolders)
firmauy sign-any-batch --input-dir ~/docs --output-dir ~/signed

# Restrict to a glob (e.g. only .zip files)
firmauy sign-any-batch --input-dir ~/docs --glob '*.zip' --output-dir ~/signed
```

Each output is named `<original-name>.p7s` inside `--output-dir` (the directory is created
automatically). The PIN can be supplied non-interactively (entered once for the whole batch) with
`--pin-source`, exactly as with the other commands. All the `sign-any` options (token,
certificate and PIN selection, `--tsa-url`, `--overwrite`) also apply.

Make sure you have reviewed all files before signing them in batch.

### Verify a signed file (auto-detect)

If you do not want to pick the right `verify-*` command, `verify` auto-detects the format by
content (PDF / XAdES XML / detached CMS `.p7s`) and dispatches to the matching verifier. Same
checks, flags and exit codes (`0` VALID, `1` INVALID, `2` INDETERMINATE).

```bash
firmauy verify signed.pdf            # detected as PDF
firmauy verify signed.xml            # detected as XAdES XML
firmauy verify document.txt.p7s      # detached: original "document.txt" located automatically
firmauy verify sig.p7s --original /path/to/document   # or point at the original explicitly
```

A PDF and an XML are self-contained, so a single argument is enough. A detached `.p7s` also
needs its original file: by default the `<x>.p7s` → `<x>` name is used, or pass `--original`.
The same `--no-trust`, `--check-revocation`, `--tsa-ca` (XAdES-T XML only), `--json`,
`--json-pretty` and `--redact` options apply. The specific commands below remain available
(clearer for scripts that know the format).

### Verify a signed XML

Verify a signed XAdES XML locally: signature integrity plus the certificate chain up to the
Uruguayan national root. No smart card is needed to verify.

The national CA certificates are **bundled with the package** (each verified against a pinned
fingerprint), so chain validation works **offline, out of the box**, with no setup needed:

```bash
# Verify (integrity + chain to the national root): bundled CAs are used automatically
firmauy verify-xml signed.xml

# Only check signature integrity, skip the certificate chain
firmauy verify-xml signed.xml --no-trust

# Override the trust anchors with your own (PEM bundle: root + intermediates)
firmauy verify-xml signed.xml --ca-file my-cas.pem

# Also check certificate revocation via CRL/OCSP (needs network)
firmauy verify-xml signed.xml --check-revocation

# XAdES-T: validate the timestamp's TSA and evaluate the cert at the trusted timestamp time
firmauy verify-xml signed.xml --tsa-ca tsa-ca.pem

# Machine-readable JSON output (for CI / other tools)
firmauy verify-xml signed.xml --json
```

Trust anchors are resolved in order: `--ca-file`, then the cache (`firmauy fetch-cas`), then the
bundled certificates. With `--no-trust`, verification reports signature integrity only (level 1).

**Trusted timestamps and long-term validation (XAdES-T).** By default a XAdES-T timestamp is only
checked to *bind* to the signature; its TSA is not validated, so the `genTime` is shown as asserted,
not verified. Pass `--tsa-ca <tsa-bundle.pem>` (the timestamping authority's certificate) to
validate the RFC 3161 token: on success the timestamp counts as **trusted time** and the signing
certificate is evaluated **at that time** instead of now, so a signature stays VALID even after the
signer's certificate later expires. There is no national TSA list to bundle, so this is
bring-your-own; PDF/CMS timestamps are validated through `--ca-file` instead. See
[docs/trust-anchors.md](docs/trust-anchors.md).

It reports a per-check breakdown and an overall indication:

- **VALID** integrity holds and the chain is trusted up to the national root.
- **INDETERMINATE** the signature is intact, but the chain is not trusted (e.g. an unknown
  issuer) or trust was skipped with `--no-trust`.
- **INVALID** the signature is broken or the document was modified after signing.

Exit codes: `0` VALID, `1` INVALID, `2` INDETERMINATE.

**JSON output.** Pass `--json` to any verify command (`verify-xml` / `verify-pdf` / `verify-any` /
`verify`) to get a single JSON object on stdout (stable `schema_version`; exit codes unchanged), suitable
for CI or integration. The `signatures` array has one entry per signature (PDFs can have several);
`signer` and `issuer` are structured:

```json
{"schema_version": 1, "redacted": false, "indication": "VALID", "signatures": [
  {"indication": "VALID", "trusted": true,
   "signer": {"common_name": "...", "serial_number": "DNI...", "organization": null,
              "country": "UY", "certificate_serial": "..."},
   "issuer": {"common_name": "Autoridad Certificadora del Ministerio del Interior",
              "serial_number": null, "organization": "Ministerio del Interior", "country": "UY"},
   "checks": [{"name": "...", "ok": true, "detail": ""}]}]}
```

On a hard error (e.g. malformed input), stdout is `{"schema_version": 1, "error": "..."}` and the
exit code is `1`.

Two modifiers (also valid on the human output):

- `--json-pretty`: like `--json` but indented for reading / pasting into issues (implies `--json`).
- `--redact`: hide personal data so a result can be shared in logs, issues or screenshots. It hides
  the signer's `common_name`, `serial_number` / document number and `certificate_serial`, and also
  blanks the free-text `detail` of every check (a chain-validation error can otherwise echo the
  certificate subject). The issuer (a public CA) is kept, unless the certificate is self-issued, in
  which case the issuer is the holder and is hidden too.

```bash
firmauy verify-pdf signed.pdf --json-pretty            # readable JSON
firmauy verify-pdf signed.pdf --json --redact          # safer to share
firmauy verify-pdf signed.pdf --redact                 # human output, signer hidden
```

Example output of `firmauy verify-pdf signed.pdf --json-pretty` (names fictitious):

```json
{
  "schema_version": 1,
  "redacted": false,
  "indication": "VALID",
  "signatures": [
    {
      "indication": "VALID",
      "signer": {
        "common_name": "PEREZ PEREZ JUAN",
        "serial_number": "DNI00000000",
        "organization": null,
        "country": "UY",
        "certificate_serial": "7A91C3D40F2E1B5A6C8D9E0F1A2B3C4D"
      },
      "issuer": {
        "common_name": "Autoridad Certificadora del Ministerio del Interior",
        "serial_number": null,
        "organization": "Ministerio del Interior",
        "country": "UY"
      },
      "trusted": true,
      "checks": [
        {"name": "signature intact (covered bytes unmodified)", "ok": true, "detail": ""},
        {"name": "signature cryptographically valid", "ok": true, "detail": ""},
        {"name": "coverage (whole file)", "ok": true, "detail": "ENTIRE_FILE"},
        {"name": "certificate chain to trusted root", "ok": true, "detail": ""}
      ]
    }
  ]
}
```

With `--redact`, the top-level `"redacted"` becomes `true`, the `signer` block above becomes
`"common_name": "[REDACTED]"`, `"serial_number": "[REDACTED]"`, `"certificate_serial": "[REDACTED]"`,
and each check `detail` becomes `"[REDACTED]"`. The issuer and the check names/results are unchanged.
The top-level `"redacted"` flag is present (as `false` by default) on the result record of every
command that supports `--redact` (`verify-*`, `list-certs`, `fetch-identity`, `fetch-photo`), so a
consumer can detect a redacted record uniformly. The verify hard-error envelope
(`{"schema_version": 1, "error": "..."}`) carries no data, so it has no `redacted` field.

What it checks: the `SignedInfo` signature, each reference digest (so any change to the document
is detected), the XAdES signing-certificate binding, and the certificate chain to a trusted root
(RFC 5280 path validation).

Revocation (CRL/OCSP) is **off by default** (offline). Enable it with `--check-revocation`,
which fetches revocation data and fails the chain if the certificate is revoked or that data
cannot be obtained.

> ⚠️ For **cédula** signatures, `--check-revocation` currently cannot succeed: the issuer's CRL
> endpoint is offline. Use the default (no `--check-revocation`). Details in
> [docs/trust-anchors.md](docs/trust-anchors.md).

**Trust anchors.** The national root and intermediate CA certificates are **bundled** with the
package and verified against pinned SHA-256 fingerprints before use, so chain validation works
**offline, out of the box**. The certificate sources, the Certificate Transparency fallback, the
pinned fingerprints, `fetch-cas` (`--from-file`) and the decommissioned CRL are documented in
**[docs/trust-anchors.md](docs/trust-anchors.md)**.

### Verify a signed PDF

Verify the signatures in a signed PDF (PAdES) locally, mirroring `verify-xml`:

```bash
firmauy verify-pdf signed.pdf
firmauy verify-pdf signed.pdf --no-trust
firmauy verify-pdf signed.pdf --ca-file my-cas.pem
firmauy verify-pdf signed.pdf --check-revocation
```

For each signature it checks integrity (intact and cryptographically valid), **coverage**
(whether the signature covers the whole file or content was added afterwards), and the
certificate chain to the national root. Trust anchors work exactly like `verify-xml`
(bundled by default; override with `--ca-file`).

Same indication model (VALID / INDETERMINATE / INVALID) and exit codes as `verify-xml`. When a
PDF has multiple signatures, the overall indication is the worst one.

> **Note on multi-signature PDFs.** When a PDF is signed more than once, each later signature
> appends content, so the **earlier** signatures no longer cover the whole file: their coverage
> check reports `ENTIRE_REVISION` (not `ENTIRE_FILE`) and the signature reads `INDETERMINATE`,
> even though it is intact. Only the most recent signature covers the whole file. This is
> deliberately conservative: it never reports a tampered PDF as valid.

### Verify a detached signature (.p7s)

Verify a detached CAdES/`.p7s` signature over a file, mirroring `verify-xml` / `verify-pdf`.
Because the signature is detached, **both** the original file and its `.p7s` are required:

```bash
# Defaults to <input>.p7s next to the file (integrity + chain to the national root)
firmauy verify-any contract.zip

# Pass the signature path explicitly
firmauy verify-any contract.zip contract.zip.p7s

# Only check signature integrity, skip the certificate chain
firmauy verify-any contract.zip --no-trust

# Use your own trust anchors / also check revocation (needs network)
firmauy verify-any contract.zip --ca-file my-cas.pem
firmauy verify-any contract.zip --check-revocation
```

It checks integrity (the signed bytes hash to the embedded digest and the signature is
cryptographically valid) and the certificate chain to the national root. Trust anchors work
exactly like `verify-xml` (bundled by default; override with `--ca-file`). A detached CMS
signature has no PDF-style coverage notion: it signs exactly the bytes it is verified against.

Same indication model (VALID / INDETERMINATE / INVALID) and exit codes as `verify-xml`.

### About verification (scope and limitations)

`verify-xml`, `verify-pdf` and `verify-any` perform a **local, technical** verification based
on open standards (XMLDSig / XAdES, PAdES, CMS / CAdES, X.509 path validation per RFC 5280, and
CRL/OCSP), anchored to the Uruguayan national root.

- This is a **technical** check, **not** the official validator. For official validation, use
  [firma.gub.uy](https://firma.gub.uy/) (see the disclaimer above).
- On the decisive questions (integrity, cryptographic validity, chain to the national root,
  revocation) the result should agree with any standards-conformant validator, because it follows
  the same standards and the same PKI, not because it reproduces any specific tool.
- It is a focused implementation: it does not cover every XAdES / PAdES profile or policy feature
  (for example signature policies, or the archival AdES levels -LT / -LTA with embedded revocation
  and archive timestamps), so verdicts may differ from other validators on edge cases. (A trusted
  timestamp can still be validated with `--tsa-ca`; see the XML verification section.)

A `VALID` result is a technical assessment, not a statement of legal validity.

### Discover tokens and certificates

List all visible PKCS#11 tokens:

```bash
firmauy list-tokens
```

List certificates available on a token:

```bash
firmauy list-certs
```

No PIN is required: on the Uruguayan ID card (cédula) the certificates are public PKCS#11 objects,
so they are read without login. (Pass `--pin-source` only if your token requires login to list them.)

With `--pem` it dumps the certificate(s) as PEM on stdout instead of the human listing, so you
can inspect or hand out your public certificate without producing a signature first:

```bash
firmauy list-certs --pem | openssl x509 -text -noout
firmauy list-certs --pem > my-cert.pem
```

This is your **leaf** certificate. It is already embedded in every signature firmauy produces
(so a verifier does not need it separately), and it is **not** a `--ca-file` trust anchor (that
expects the national root, which is bundled).

For automation, `--json` (or `--json-pretty`) emits the list as structured JSON (`schema_version` 1,
with a top-level `redacted` flag), handy to pick a certificate programmatically (its `id` feeds
`--cert-id`). With `--pem` each entry also gets a `pem` field; with `--redact` the holder's personal
data (subject common name, document number, certificate serial and PEM) is hidden for sharing,
keeping the issuer:

```bash
firmauy list-certs --json-pretty                 # structured, readable
firmauy list-certs --json --redact               # safer to share (no personal data)
```

### Diagnose your setup (doctor)

`firmauy doctor` checks the local environment and reports `PASS` / `WARN` / `FAIL` for each
prerequisite (PKCS#11 module, `pcscd`, card detection, bundled CAs), with a remediation hint
for anything that is not OK. It needs no PIN. Exit code: `0` if there are no `FAIL`s, `1`
otherwise (warnings do not fail).

```bash
firmauy doctor
firmauy doctor --json        # machine-readable (schema_version 1)
```

Example:

```text
PASS  firmauy: 0.9.0 (Python 3.14.3)
PASS  PKCS#11 module present: /usr/lib/pkcs11/libgclib.so
PASS  pcscd running
WARN  cédula token detected: no card found
      → Insert the cédula and check the reader connection / pcscd.
PASS  bundled national CA certificates: root + intermediate loaded
```

### Read biographical data from the card

`firmauy fetch-identity` reads the biographical data stored in the card's AIS applet (names, birth date, nationality, birthplace, document number and MRZ) directly via PC/SC. This data is accessible from the card without PIN authentication, but it is still **personal data**. The applet, file identifiers and APDUs follow [AGESIC's public technical documentation](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/documentacion-tecnica-id-uruguay/documentacion-tecnica-id-uruguay-9) for the ID Uruguay card (ISO/IEC 7816, ICAO 9303).

> ⚠️ Do not run `fetch-identity` while a `sign-*` command is active on the same card. Both paths go through `pcscd` and may conflict on the same card connection.

```bash
# List available PC/SC readers
firmauy list-readers

# Fetch identity data (auto-detects reader if only one is present)
firmauy fetch-identity

# Specify a reader by name (as shown by list-readers)
firmauy fetch-identity --reader "Alcor Link AK9563 00 00"

# Machine-readable JSON output
firmauy fetch-identity --json

# Indented JSON (implies --json)
firmauy fetch-identity --json-pretty

# Hide every biographical field (all of it is the cardholder's data) for sharing the output
firmauy fetch-identity --redact
firmauy fetch-identity --json --redact
```

Human output example:

```text
╔════════════════════════════════════════════════════════╗
║             CÉDULA DE IDENTIDAD - URUGUAY              ║
╠════════════════════════════════════════════════════════╣
║  Número de documento       00000TXXXX                  ║
╟────────────────────────────────────────────────────────╢
║  Primer apellido           EJEMPLO                     ║
║  Segundo apellido          FICTICIO                    ║
║  Nombre(s)                 NOMBRE EJEMPLO              ║
║  Nacionalidad              URY                         ║
║  Fecha de nacimiento       01/01/1970                  ║
║  Lugar de nacimiento       MONTEVIDEO/URY              ║
║  Número de cédula          00000000                    ║
║  Fecha de vencimiento      01/01/2099                  ║
╠════════════════════════════════════════════════════════╣
║                          MRZ                           ║
╠════════════════════════════════════════════════════════╣
║  I<URY00000TXXXX1000000000<<<<<<<<                     ║
║  7001010<9901010URY000000000<<<<<0                     ║
║  EJEMPLO<FICTICIO<<NOMBRE<EJEMPLO<                     ║
╚════════════════════════════════════════════════════════╝
```

JSON output (`--json-pretty`):

```json
{
  "schema_version": 1,
  "redacted": false,
  "first_lastname": "EJEMPLO",
  "second_lastname": "FICTICIO",
  "given_names": "NOMBRE EJEMPLO",
  "nationality": "URY",
  "birth_date": "01/01/1970",
  "birthplace": "MONTEVIDEO/URY",
  "id_number": "00000000",
  "id_number_check_digit_valid": true,
  "expiry_date": "01/01/2099",
  "document_number": "00000TXXXX",
  "mrz": [
    "I<URY00000TXXXX1000000000<<<<<<<<",
    "7001010<9901010URY000000000<<<<<0",
    "EJEMPLO<FICTICIO<<NOMBRE<EJEMPLO<"
  ]
}
```

Fields absent on a specific card (e.g. no second lastname) are omitted from the output. The `schema_version` field follows the same stable contract as the verify commands. Exit codes: `0` on success, `1` on any error (no reader, no card, APDU failure).

### Read the cardholder's photo

`firmauy fetch-photo` saves the cardholder's photo (a JPEG, AIS file `7004`) to a file. Like the biographical data, this data is accessible from the card without PIN authentication, but it is still **personal data**. By default it writes a file; pass `-` as the output to stream the raw JPEG to **stdout** instead, so you can pipe or redirect it. To avoid dumping binary to the screen, streaming to an **interactive terminal is refused** (redirect or pipe it).

```bash
firmauy fetch-photo                      # saves to cedula_foto.jpg
firmauy fetch-photo cedula_foto.jpg      # explicit output path
firmauy fetch-photo --reader "..."       # select a reader (see list-readers)
firmauy fetch-photo --overwrite          # replace an existing output file
firmauy fetch-photo - > cedula_foto.jpg  # stream the raw JPEG to stdout (redirect)
firmauy fetch-photo - | feh -            # ...or pipe it straight to a viewer, no file on disk
firmauy fetch-photo --json               # a JSON record (metadata + base64 image) on stdout
firmauy fetch-photo --json-pretty        # ...indented for humans (implies --json)
firmauy fetch-photo --json --redact      # ...without the image or any correlatable value
```

With `--json` (or `--json-pretty`) a self-describing record is written to stdout instead of the raw image: `format`, `mime`, pixel `width`/`height`, `bytes`, the `sha256` and the `base64`-encoded image, alongside `schema_version` and the top-level `redacted` flag. It pairs with `fetch-identity --json` and embeds anywhere a data URI does (`data:image/jpeg;base64,...`).

```json
{ "schema_version": 1, "redacted": false, "format": "jpeg", "mime": "image/jpeg",
  "width": 240, "height": 320, "bytes": 10159, "sha256": "...", "base64": "/9j/4AAQ..." }
```

`--redact` drops the image **and** every value that could fingerprint or correlate the cardholder (the `sha256` of a face photo is a stable per-card identifier, and the byte count leaks the same way), leaving only the non-identifying shape of the file (format, MIME type, dimensions) plus `redacted: true`. The sensitive keys are **omitted rather than stringified**, so the record stays well-typed and is safer to log or share:

```json
{ "schema_version": 1, "redacted": true, "format": "jpeg", "mime": "image/jpeg", "width": 240, "height": 320 }
```

The same caveat as `fetch-identity` applies: do not run it while a `sign-*` command is active on the same card. The photo is the most sensitive field on the card, so treat the output file, redirected stream, or receiving application accordingly.

### Validate a cédula number (check digit)

`firmauy validate-ci` checks the check digit of a Uruguayan cédula number. **No card, PIN or network
is needed**: it is a purely arithmetic consistency check.

> ⚠️ This validates **only the mathematical consistency** of the number (its check digit). It does
> **not** validate identity, the existence or current validity of a person, the validity of a
> document, or the authenticity of a card. It catches typos and obviously malformed numbers, nothing
> more.

```bash
firmauy validate-ci 1.234.567-2          # accepts dots and dash, or plain digits
firmauy validate-ci 12345672             # -> VALID    (exit 0)
firmauy validate-ci 12345678             # -> INVALID  (exit 1; expected check digit 2)
firmauy validate-ci 1234567 --complete   # a body without its check digit -> 12345672
firmauy validate-ci 12345672 --json
firmauy validate-ci 12345672 --json --redact
```

Exit codes make it scriptable: `0` valid, `1` invalid, `2` malformed input. The JSON record carries
the usual `schema_version` and the top-level `redacted` flag:

```json
{ "schema_version": 1, "redacted": false, "valid": true, "input": "1.234.567-2",
  "normalized": "12345672", "body": "1234567", "check_digit": "2", "expected_check_digit": "2" }
```

With `--redact` the number (personal data) is dropped, keeping only the verdict:

```json
{ "schema_version": 1, "redacted": true, "valid": true }
```

The same check is surfaced in `fetch-identity --json` as `"id_number_check_digit_valid": true`,
computed from the card's cédula number and present even under `--redact`.

## Security considerations

- Never pass the PIN directly as a command-line argument.
- Prefer interactive PIN entry for manual use.
- For automation, prefer protected file descriptors or controlled environments.
- Review every document before signing it.
- Use batch signing only in trusted workflows.
- Keep your smart card, reader, PIN, and PKCS#11 middleware under your own control.

## Privacy

This tool is designed to run entirely locally.

It does not collect, transmit, or store any user data externally.

All cryptographic operations are performed on the user's machine and/or the connected smart card.

Note: Optional features such as timestamping (TSA) may involve external network requests, depending on user configuration.

Note: the signing commands print a summary that includes identifying data (signer name, certificate issuer, certificate serial number and PKCS#11 key ID). This stays on your machine, but in batch or automated pipelines that output can end up in CI or centralized logs. Pass `--quiet` (`-q`) to the `sign-pdf`, `sign-pdf-batch`, `sign-xml`, `sign-xml-batch`, `sign-any` and `sign-any-batch` commands to suppress that block while still signing.

Note: `fetch-identity` reads and prints the cardholder's biographical data (names, birth date, birthplace, document number, MRZ), and `fetch-photo` outputs the cardholder's photo (to a file, a redirected stream, or a JSON record). This data is accessible from the card without PIN authentication, but it is still personal: pass `--redact` to `fetch-identity` to replace every field with `[REDACTED]` before sharing its output, use `fetch-photo --json --redact` for a metadata-only photo record, and treat any non-redacted output (file, redirected stream, or receiving application) as sensitive.

## Signature verification

For **authoritative** verification, especially for any legal or official purpose, use the official validator provided by AGESIC (no affiliation implied):

[https://firma.gub.uy/](https://firma.gub.uy/)

This tool also verifies signatures **locally** (`firmauy verify-pdf` / `verify-xml` / `verify-any`, with chain validation to the Uruguayan national root, no smart card needed; see [Usage](#usage)). That is a convenient technical check, **not** a replacement for the official validator.

Note that a successful **technical** verification does not by itself imply **legal** validity for every use case. See [Legal and compliance](#legal-and-compliance).

## Additional notes

- The default visual signature appearance was modeled on real documents signed with the Uruguayan ID card.
- This project focuses on practical interoperability rather than strict compliance with any specific implementation.

## Legal and compliance

This project is copyright-registered, experimental, community-maintained, and not officially certified.

It is intended for developers and technically proficient users who understand the implications of using smart cards, PKCS#11 middleware, and digital signatures.

**This project:**

- is **not affiliated with or endorsed by AGESIC**
- does **not** claim official certification or compliance
- does **not** guarantee the legal validity of generated signatures
- is provided **for technical and educational purposes**

While it uses standard cryptographic mechanisms and aims to align with Uruguayan digital signature practices, the generated signatures should not be assumed valid for legal or regulatory use without independent verification. Users are solely responsible for ensuring that generated signatures meet any legal or regulatory requirements applicable to their use case.

### Intended use

Local, developer-oriented signing and verification using a Uruguayan ID card through PKCS#11. It is especially aimed at users who want to:

- sign PDFs (PAdES), XML documents (XAdES), and arbitrary files (CAdES/.p7s) locally
- verify those signatures locally, including the certificate chain to the national root
- understand and reproduce a PKCS#11-based signing workflow
- experiment with smart card integration on Linux
- build automation around signing and verification under their own responsibility

It is **not** intended to replace official, certified, or legally guaranteed signing platforms.

### Scope

This tool focuses on technical integration with PKCS#11: signing (PDF/PAdES, XML/XAdES, files/CAdES) and local, standards-based verification, including certificate-chain validation to the Uruguayan national root.

It is **not** an official validator: it does not consult the official trust-service status list (TSL) or evaluate accreditation / qualified status, provide legal guarantees, or replace certified signing platforms.

## Copyright / software registration

This software has been registered as a computer program with the Uruguayan Dirección Nacional de la Propiedad Industrial y Registro de Software.

The registration was published in the official Boletín de la Propiedad Industrial Nº 357:

- Entry: Software (w/000235)
- Filing date: 2026-04-15
- Applicant: Carlos Andrés Planchón Prestes [UY]
- Title: cedula-uy-pdf-sign
- Classification: Programa de ordenador
- Official publication: [Boletín de la Propiedad Industrial Nº 357](https://www.gub.uy/ministerio-industria-energia-mineria/sites/ministerio-industria-energia-mineria/files/documentos/publicaciones/Boletin%20357.pdf)

The project was later renamed to **FirmaUY** (PyPI package and CLI: `firmauy`). The registration above is under its original title, `cedula-uy-pdf-sign`.

This registration concerns the authorship of the software as a copyrighted work. It does **not** imply official certification, endorsement, legal validity of generated signatures, or regulatory compliance of any specific use case. See [Legal and compliance](#legal-and-compliance).

## Development

The project uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

```bash
# Clone the repository
git clone https://github.com/carlosplanchon/firmauy.git
cd firmauy

# Create the environment and install dependencies (runtime + dev)
uv sync

# Run the test suite (PKCS#11 integration tests need SoftHSM2, see below)
uv run pytest

# Run the CLI from the working tree
uv run firmauy --help
```

The package source lives under `src/firmauy/`; tests under `tests/`.

### Developing without the real card (SoftHSM2)

Entering the wrong PIN too many times **blocks the cédula**, so develop against a software PKCS#11
token (SoftHSM2) instead of the card. The setup, the throwaway "fake cédula" provisioning script
(`scripts/dev-softhsm-setup.sh`), the iterate-without-the-card loop and how the integration tests
use it are documented in **[docs/development.md](docs/development.md)**.

## Contributing & reporting issues

Bug reports, questions, and pull requests are welcome.

Feel free to open an issue on GitHub.

### Cookbook contributions welcome

Cookbook recipes (see **[docs/cookbook.md](docs/cookbook.md)**) are welcome, and one of the best ways
to help: they open the project to people who will not necessarily touch the PKCS#11, APDU or XAdES
internals but can still share real, useful workflows. A good recipe shows a real workflow with
minimal commands, the expected output, privacy notes, and the environment where it was tested.

Please do not include real names, document numbers, MRZ data, certificates, photos, or unredacted
verification output. Use `--redact` whenever sharing command output.

## Acknowledgements

- [@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev): contributed the `fetch-identity` and `list-readers` commands for reading the cardholder's biographical data over PC/SC ([#1](https://github.com/carlosplanchon/firmauy/pull/1)). Also provided reference for the signature appearance inspired by signatures generated using the Uruguayan ID card (cédula), and helped test the XAdES (XML) signing feature.

## License

This project is licensed under the Apache License 2.0.
