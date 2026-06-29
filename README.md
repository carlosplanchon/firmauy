# cedula-uy-pdf-sign

![cedula-uy-pdf-sign banner](https://raw.githubusercontent.com/carlosplanchon/cedula-uy-pdf-sign/main/assets/banner.jpg)

Sign PDF and XML documents locally using a Uruguayan national ID card (cédula) through PKCS#11, producing standards-based PDF and XML (XAdES) digital signatures that verify with standard signature validators.

[![PyPI version](https://img.shields.io/pypi/v/cedula-uy-pdf-sign.svg)](https://pypi.org/project/cedula-uy-pdf-sign/)
[![Python versions](https://img.shields.io/pypi/pyversions/cedula-uy-pdf-sign.svg)](https://pypi.org/project/cedula-uy-pdf-sign/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/cedula-uy-pdf-sign)

> ⚠️ **Disclaimer**: This is an experimental, community-maintained project. It is **not affiliated with or endorsed by AGESIC**, is **not officially certified**, and **does not guarantee the legal validity** of the signatures it produces. Use at your own risk. See [Legal and compliance](#legal-and-compliance) for details.

## Quick start

> Requires **Linux** with the Uruguayan cédula PKCS#11 middleware installed. The full smart-card setup is in [Requirements](#requirements) and [Setup on Arch Linux](#setup-on-arch-linux).

```bash
uv tool install cedula-uy-pdf-sign     # install
firmauy list-tokens                    # verify the card is detected
firmauy sign-pdf input.pdf                 # sign -> input_firmado.pdf (prompts for the PIN)
```

## Overview

`cedula-uy-pdf-sign` provides a local, developer-oriented workflow for signing PDF documents with a Uruguayan national ID card using PKCS#11 middleware.

The CLI tool is invoked as `firmauy` and supports:

- signing individual PDF documents
- batch-signing multiple PDFs with a single PKCS#11 session
- signing XML documents, individually or in batch (XAdES-BES, enveloped)
- signing arbitrary files, individually or in batch (CAdES-BES detached `.p7s`, CMS/PKCS#7)
- verifying signed PDF, XML and detached `.p7s` files locally, with chain validation to the national root
- configuring the visible signature position
- selecting the signature page
- discovering available PKCS#11 tokens and certificates
- non-interactive PIN sources for controlled automation workflows

## Requirements

### Hardware

- Smart card reader compatible with your OS
- Uruguayan ID card (cédula) with active certificate

### Operating system

This tool targets **Linux** and is primarily developed and tested on **Arch Linux**.

Other Linux distributions may work if the required smart card stack, PKCS#11 middleware, and Python environment are correctly configured.

**Windows and macOS are not supported.**

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
uv tool install cedula-uy-pdf-sign
```

## Usage

The CLI tool is invoked as `firmauy`.

### CLI help

Use `--help` on any command to see all available options:

```bash
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

### Custom signature position

```bash
firmauy sign-pdf input.pdf output_signed.pdf --x1 20 --y1 20 --x2 225 --y2 90
```

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

Embed a trusted timestamp from a Time Stamping Authority:

```bash
firmauy sign-pdf input.pdf output_signed.pdf --tsa-url https://your-tsa/endpoint
```

TSA timestamping is **optional** and is **not required** for the standard Uruguayan cédula signing flow. It adds independent, trusted-time evidence to the signature and may involve an external network request.

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
signature following the XAdES specification (ETSI EN 319 132). It verifies with standard XAdES
validators and is suitable for signing structured documents such as electronic fiscal documents
(CFE / facturación electrónica).

```bash
firmauy sign-xml input.xml output_signed.xml
```

If the output path is omitted, the signed file is saved as `<input>_firmado.xml`.

Token discovery, certificate selection and PIN handling work exactly like the PDF commands, so
the same options apply: `--token-label`, `--cert-id`, `--pin-source` (with `--pin-env-var` /
`--pin-fd`), `--timezone` and `--overwrite`.

```bash
# Non-interactive PIN, same as the PDF commands
echo "1234" | firmauy sign-xml input.xml output_signed.xml --pin-source stdin
```

Signature profile produced:

- **Format:** XAdES-BES, enveloped; the `<ds:Signature>` is appended as the last child of the
  document root, with a single reference over the whole document (`URI=""`).
- **Canonicalization:** inclusive C14N 1.0 (`REC-xml-c14n-20010315`).
- **Algorithms:** RSA-SHA256 signature, SHA-256 digests.
- **Signed properties:** signing time, signing-certificate digest and data-object format.

⚠️ This is the XAdES-**BES** level (no trusted timestamp). The produced signature is
cryptographically valid and conforms to the XAdES standard; legal and regulatory validity
depends on your use case and applicable rules.

### Sign multiple XML documents (batch)

Sign many XML files with a single PKCS#11 session (the card PIN is entered only once). This
mirrors `sign-pdf-batch` for PDFs and is convenient for bulk workflows such as electronic invoicing.

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

### Sign any file (CAdES / .p7s)

Sign **any file** — not just PDF or XML — with the cédula, producing a standards-based
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

### Verify a signed XML

Verify a signed XAdES XML locally: signature integrity plus, when trust anchors are available,
the certificate chain up to the Uruguayan national root. No smart card is needed to verify.

This project does **not** redistribute the state CA certificates. To enable chain validation,
fetch them once from their official sources (the national root is checked against a pinned
fingerprint and cached locally), or supply your own with `--ca-file`:

```bash
# Cache the national CAs from their official sources (one time)
firmauy fetch-cas

# Verify (integrity + chain to the national root, using the cached CAs)
firmauy verify-xml signed.xml

# Only check signature integrity, skip the certificate chain
firmauy verify-xml signed.xml --no-trust

# Use your own trust anchors instead (PEM bundle: root + intermediates)
firmauy verify-xml signed.xml --ca-file my-cas.pem

# Also check certificate revocation via CRL/OCSP (needs network)
firmauy verify-xml signed.xml --check-revocation
```

Without cached CAs or `--ca-file`, verification falls back to signature integrity only (level 1).

It reports a per-check breakdown and an overall indication:

- **VALID** integrity holds and the chain is trusted up to the national root.
- **INDETERMINATE** the signature is intact, but the chain is not trusted (e.g. an unknown
  issuer) or trust was skipped with `--no-trust`.
- **INVALID** the signature is broken or the document was modified after signing.

Exit codes: `0` VALID, `1` INVALID, `2` INDETERMINATE.

What it checks: the `SignedInfo` signature, each reference digest (so any change to the document
is detected), the XAdES signing-certificate binding, and the certificate chain to a trusted root
(RFC 5280 path validation).

Revocation (CRL/OCSP) is **off by default** (offline). Enable it with `--check-revocation`,
which fetches revocation data and fails the chain if the certificate is revoked or that data
cannot be obtained.

⚠️ Limitations: since XAdES-BES carries no trusted timestamp, certificate validity and revocation
are evaluated at verification time, not at signing time. The national CA certificates rotate and
expire; re-run `firmauy fetch-cas` to refresh the cache, or use `--ca-file`.

#### Trust anchors: sources and pinned fingerprints

`fetch-cas` downloads the certificates and verifies **each** against a pinned SHA-256
fingerprint before caching (the certificate bytes are not redistributed by this project —
only the hashes are). The intermediate is, in addition, checked to be signed by the root.

| Certificate | Source(s), tried in order |
|---|---|
| AC Raíz Nacional de Uruguay (AGESIC) | `https://www.uce.gub.uy/acrn/acrn.cer` |
| AC Ministerio del Interior (intermediate) | `https://ca.minterior.gub.uy/certificados/MICA.cer` (official), then `https://crt.sh/?d=29172099` (fallback) |

> **Note on the intermediate source.** The Ministerio del Interior CA repository
> (`ca.minterior.gub.uy`) has been decommissioned and now returns `HTTP 501` for every
> request, and AGESIC's trust-list page still points at that dead URL. `fetch-cas`
> therefore falls back to the **byte-identical** copy in the public Certificate
> Transparency log (crt.sh), retrying transient errors. This is safe regardless of the
> source: the bytes are accepted only if they match the pinned fingerprint below *and*
> are signed by the pinned root. If the official server is restored, it is used first.

Pinned fingerprints (SHA-256 of each certificate, DER):

```text
root (ACRN):        5533a0401f612c688ebce5bf53f2ec14a734eb178bfae00e50e85dae6723078a
intermediate (MICA): a29cad5c89aa49cff81f17f45c42fd44685510246d9ab5d031448e2fda2517be
```

You can audit them yourself:

```bash
# Root, from the official source:
curl -s https://www.uce.gub.uy/acrn/acrn.cer | openssl x509 -noout -fingerprint -sha256
# SHA256 Fingerprint=55:33:A0:40:...:8A  (same bytes, openssl prints them upper-case with colons)

# Intermediate, from the Certificate Transparency log:
curl -s -A "firmauy (+https://pypi.org/project/cedula-uy-pdf-sign)" "https://crt.sh/?d=29172099" \
  | openssl x509 -noout -fingerprint -sha256
# SHA256 Fingerprint=A2:9C:AD:5C:...:BE
```

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
(run `firmauy fetch-cas` once, or pass `--ca-file`).

Same indication model (VALID / INDETERMINATE / INVALID) and exit codes as `verify-xml`. When a
PDF has multiple signatures, the overall indication is the worst one.

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
exactly like `verify-xml` (run `firmauy fetch-cas` once, or pass `--ca-file`). A detached CMS
signature has no PDF-style coverage notion: it signs exactly the bytes it is verified against.

Same indication model (VALID / INDETERMINATE / INVALID) and exit codes as `verify-xml`.

### About verification (scope and limitations)

`verify-xml`, `verify-pdf` and `verify-any` perform a **local, technical** verification based
on open standards (XMLDSig / XAdES, PAdES, CMS / CAdES, X.509 path validation per RFC 5280, and
CRL/OCSP), anchored to the Uruguayan national root.

- This is **not** the official validator and does **not** provide an official or legally binding
  validation. For legal validity, use the official channels.
- On the decisive questions (integrity, cryptographic validity, chain to the national root,
  revocation) the result should agree with any standards-conformant validator, because it follows
  the same standards and the same PKI, not because it reproduces any specific tool.
- It is a focused implementation: it does not cover every XAdES / PAdES profile or policy feature
  (for example signature policies or long-term / archival levels), so verdicts may differ from
  other validators on edge cases.

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

Note: the signing commands print a summary that includes identifying data (signer name, certificate issuer, certificate serial number and PKCS#11 key ID). This stays on your machine, but in batch or automated pipelines that output can end up in CI or centralized logs. Pass `--quiet` (`-q`) to the `sign-pdf`, `sign-pdf-batch`, `sign-xml` and `sign-xml-batch` commands to suppress that block while still signing.

## Signature verification

Signed documents can be independently verified using external tools, such as the official validator provided by AGESIC (no affiliation implied):

[https://firma.gub.uy/](https://firma.gub.uy/)

Note that a successful **technical** verification does not by itself imply **legal** validity for every use case. See [Legal and compliance](#legal-and-compliance).

## Additional notes

- The default visual signature appearance was derived by analyzing documents signed with official software.
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

Local, developer-oriented PDF signing using a Uruguayan ID card through PKCS#11. It is especially aimed at users who want to:

- sign PDF documents locally
- understand and reproduce a PKCS#11-based signing workflow
- experiment with smart card integration on Linux
- build automation around PDF signing under their own responsibility

It is **not** intended to replace official, certified, or legally guaranteed signing platforms.

### Scope

This tool focuses on technical integration with PKCS#11, PDF signing workflows, and reproducibility of signature appearance.

It does **not** validate certificates against official trust lists, provide legal guarantees, or replace certified signing platforms.

## Copyright / software registration

This software has been registered as a computer program with the Uruguayan Dirección Nacional de la Propiedad Industrial y Registro de Software.

The registration was published in the official Boletín de la Propiedad Industrial Nº 357:

- Entry: Software (w/000235)
- Filing date: 2026-04-15
- Applicant: Carlos Andrés Planchón Prestes [UY]
- Title: cedula-uy-pdf-sign
- Classification: Programa de ordenador
- Official publication: [Boletín de la Propiedad Industrial Nº 357](https://www.gub.uy/ministerio-industria-energia-mineria/sites/ministerio-industria-energia-mineria/files/documentos/publicaciones/Boletin%20357.pdf)

This registration concerns the authorship of the software as a copyrighted work. It does **not** imply official certification, endorsement, legal validity of generated signatures, or regulatory compliance of any specific use case. See [Legal and compliance](#legal-and-compliance).

## Development

The project uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

```bash
# Clone the repository
git clone https://github.com/carlosplanchon/cedula-uy-pdf-sign.git
cd cedula-uy-pdf-sign

# Create the environment and install dependencies (runtime + dev)
uv sync

# Run the test suite (PKCS#11 integration tests need SoftHSM2, see below)
uv run pytest

# Run the CLI from the working tree
uv run firmauy --help
```

The package source lives under `src/cedula_uy_pdf_sign/`; tests under `tests/`.

### Developing without the real card (SoftHSM2)

Entering the wrong PIN too many times **blocks the cédula**, so you should not develop against the real card. Instead, you can run the full signing pipeline against a software PKCS#11 token (SoftHSM2) that mimics a cédula closely enough to exercise token discovery, certificate selection, PIN handling and signing.

```bash
# Arch Linux: install the software token + tooling
sudo pacman -S softhsm opensc openssl

# Provision a throwaway "fake cédula" token under ./.softhsm
bash scripts/dev-softhsm-setup.sh
```

The script prints ready-to-run `firmauy list-certs` / `firmauy sign-pdf` commands pointing at the SoftHSM module. The resulting PDF is a cryptographically valid signature, but it will **not** validate as a *cédula* signature on [firma.gub.uy](https://firma.gub.uy/) (the issuing CA is a local fake, by design). Reset everything with `rm -rf .softhsm`.

The token persists under `.softhsm`, so this doubles as a normal development loop: run `firmauy` by hand as often as you like (signing test PDFs, trying signature positions with `--x1/--y1/...`, exercising `sign-pdf-batch`, reproducing a reported bug) while iterating on the code, without the card and without risking PIN lockout. The real card is then only needed for a final validation run and for middleware-specific behaviour.

The same setup powers a set of end-to-end integration tests (`tests/test_integration_pkcs11.py`) that exercise the real PKCS#11 path: signing plus cryptographic verification of the resulting PDF, and the selection/error branches that are unsafe to reproduce on the real card (expired certificate, certificate without a private key, multiple tokens, certificate scoring and `--cert-id` override). They are **skipped automatically** when SoftHSM2 / OpenSC / OpenSSL are not installed, so `uv run pytest` works either way.

## Contributing & reporting issues

Bug reports, questions, and pull requests are welcome.

Feel free to open an issue on GitHub.

## Acknowledgements

- [@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev): provided reference for the signature appearance inspired by signatures generated using the Uruguayan ID card (cédula), and helped test the XAdES (XML) signing feature.

## License

This project is licensed under the Apache License 2.0.
