# FirmaUY

![FirmaUY banner](https://raw.githubusercontent.com/carlosplanchon/firmauy/main/assets/banner_firmauy.jpg)

**Your cédula is a signing key. FirmaUY brings it to the terminal.**

Sign and verify PDF, XML and any file with your Uruguayan national ID card over PKCS#11. Open-standard signatures (PAdES, XAdES, CAdES) designed to interoperate with compliant validators, with the whole trust chain checked locally against the Uruguayan national root. Signing and verifying keep your documents on your machine. Use it from the terminal, or from Python through its [public API](#use-as-a-library).

[![CI](https://github.com/carlosplanchon/firmauy/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosplanchon/firmauy/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/firmauy.svg)](https://pypi.org/project/firmauy/)
[![Python versions](https://img.shields.io/pypi/pyversions/firmauy.svg)](https://pypi.org/project/firmauy/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/firmauy)

> ⚠️ **Disclaimer**: This tool performs **local, technical** signing and verification using open standards. It is experimental, community-maintained, **not affiliated with AGESIC**, **not officially certified**, and **does not guarantee legal validity**. For official validation, use the [official AGESIC validator](https://firma.gub.uy/); see [Legal and compliance](#legal-and-compliance) for details.

> ✅ **Always cross-check what you sign.** Before sending or relying on a signed document, upload
> it to [firma.gub.uy](https://firma.gub.uy/), the State validator, and keep its answer. Every
> time, for every document that matters. firmauy checking its own output is not independent
> evidence, and the arbiter your counterparty will use is the State's validator: agreement with
> it is [tracked, not assumed](docs/security-invariants.md#the-conformance-protocol). The
> cross-check is also the one recommended step that leaves your machine: uploading sends the
> document to a State-operated service, so for confidential material do it through whatever
> channel your situation allows. The portal validates PDF, so a detached `.p7s` cannot be
> checked there, which is worth weighing when you choose a format for something important.

## Quick start

> Requires **Linux** with the Uruguayan cédula PKCS#11 middleware installed. The full smart-card setup is in [Requirements](#requirements) and [Setup on Arch Linux](#setup-on-arch-linux).

```bash
uv tool install firmauy                # install
firmauy doctor                         # check the setup (pcscd, PKCS#11 module, card, CAs)
firmauy list-tokens                    # confirm the card is detected
firmauy sign-pdf input.pdf             # sign -> input_firmado.pdf (prompts for the PIN)
firmauy verify input_firmado.pdf       # verify (auto-detects format; offline chain check)
```

Then upload `input_firmado.pdf` at [firma.gub.uy](https://firma.gub.uy/). **Always.** See the
disclaimer above for why.

## Overview

FirmaUY provides a local, developer-oriented workflow for **signing and verifying** documents and files with a Uruguayan national ID card (cédula) using PKCS#11 middleware: PDF (PAdES), XML (XAdES) and detached CAdES/.p7s signatures for arbitrary files.

Each format has a batch variant and optional RFC 3161 timestamping. Verification runs locally with certificate-chain validation to the Uruguayan national root, and needs no card. FirmaUY also reads the card's public data without a PIN (biographical data and photo), validates a cédula's check digit offline, and diagnoses the local setup.

Everything the CLI does is also a public Python API with typed results and typed errors,
`firmauy.api`, built on the same engine: see [Use as a library](#use-as-a-library).

See [Commands](#commands) for the full list, with every command's options behind `firmauy <command> --help`.

## Supported signature formats

| Format | Command | Output | Verification | Timestamping |
|---|---|---|---|---|
| PDF / PAdES | `sign-pdf` | signed `.pdf` | `verify-pdf` / `verify` | optional (external TSA) |
| XML / XAdES | `sign-xml` | signed `.xml` | `verify-xml` / `verify` | optional (external TSA) |
| Any file / CAdES | `sign-any` | detached `.p7s` | `verify-any` / `verify` | optional (external TSA) |

The full AdES triad (PAdES / XAdES / CAdES), signed locally with the cédula and verifiable with
standard validators; local verification anchors the chain to the Uruguayan national root. Each
command has a batch variant (`sign-pdf-batch`, `sign-xml-batch`, `sign-any-batch`). The default PDF
(PAdES) signature has a visible appearance modeled on real documents signed with the Uruguayan ID
card.

Timestamping is **optional and bring-your-own**: it works with any external RFC 3161 TSA via
`--tsa-url`, but it is **not** part of the standard cédula flow, and Uruguay has no free public TSA
(the accredited qualified ones are gated). See [Timestamping](docs/usage.md#timestamping-tsa-optional).

## Requirements

### Hardware

- Smart card reader compatible with your OS
- Uruguayan ID card (cédula) with active certificate

### Operating system

This tool targets **Linux** and is primarily developed and tested on **Arch Linux**.

Other Linux distributions may work if the required smart card stack, PKCS#11 middleware, and Python environment are correctly configured.

**Windows** (x64) is supported from 1.21.0: signing, `doctor` and the native PC/SC backend. There,
PC/SC is the built-in Smart Card service, which Windows starts when a reader is plugged in, and the
PKCS#11 middleware is Thales Classic Client: the default module is
`C:\Program Files\Thales\Classic Client\BIN\gclib.dll`, the 64-bit one. The installer also puts a
32-bit copy under `Program Files (x86)`, which a 64-bit Python cannot load. On Windows the signed
file inherits its folder's permissions, and nothing is carried over from a file it replaces.

**macOS is not currently supported or tested.**

### Python

Python **3.11 or newer**.

### PKCS#11 middleware

The tool expects the Uruguayan cédula PKCS#11 module (`/usr/lib/pkcs11/libgclib.so`), provided on
Arch Linux by the `cedula-uruguay-pkcs11` AUR package. Install it as shown in
[Setup on Arch Linux](#setup-on-arch-linux).

> **Native mode (optional):** every signing command also accepts `--native`, which talks to the
> cédula directly over PC/SC (pcscd and a reader) and needs **no PKCS#11 middleware** at all. It is
> experimental and not officially certified, though its output is accepted by the AGESIC validator.
> See [Native signing](docs/usage.md#native-signing-no-pkcs11-middleware) and the
> [card protocol reference](docs/card-protocol.md). `firmauy doctor --native` diagnoses this
> path (reader and card over PC/SC) instead of the PKCS#11 module.

> **OpenSC backend (merged upstream, pending release):**
> [@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev) and I added support for the
> Uruguayan cédula to [OpenSC](https://github.com/OpenSC/OpenSC), the open-source smart-card
> framework, so the card can be used through a fully open-source PKCS#11 module (`opensc-pkcs11.so`)
> instead of the proprietary `libgclib.so`. The driver is merged upstream and signs end to end. It
> is not in a released OpenSC version yet, so for now you build from source. See
> [Signing with the OpenSC backend](docs/opensc-backend.md).

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

FirmaUY is published on PyPI. Install it as a standalone CLI with [`uv`](https://docs.astral.sh/uv/)
(recommended) or into your current environment with `pip`:

```bash
uv tool install firmauy      # recommended: isolated CLI on your PATH
pip install firmauy          # or into the current Python environment
```

Installing the package does **not** install the smart-card stack. You still need `pcscd`, a reader
and the PKCS#11 middleware (or `--native`, which needs only `pcscd`). See
[Requirements](#requirements) and [Setup on Arch Linux](#setup-on-arch-linux), then run
`firmauy doctor` to check everything is in place.

## Commands

Run `firmauy --help`, or `firmauy <command> --help` for the full options of any command. Step-by-step
examples for every command are in the **[usage guide](docs/usage.md)**, and task-oriented recipes
(privacy, automation, `jq` pipelines) are in the **[cookbook](docs/cookbook.md)**.

**Signing** (prompts for the card's PIN, unless a [non-interactive source](docs/usage.md#non-interactive-pin) is given). Add [`--native`](docs/usage.md#native-signing-no-pkcs11-middleware) to any of these to sign over PC/SC without PKCS#11:

| Command | Description |
|---|---|
| `sign` / `sign-batch` | Sign a file (or a mixed folder in one session), auto-detecting the type: PDF -> PAdES, XML -> XAdES, anything else -> detached CAdES. `--as` forces the type |
| `sign-pdf` / `sign-pdf-batch` | Sign a PDF, or a whole folder in one session, with a visible signature (PAdES) |
| `sign-xml` / `sign-xml-batch` | Sign XML documents (XAdES-BES, or XAdES-T with `--tsa-url`) |
| `sign-any` / `sign-any-batch` | Produce a detached `.p7s` for any file (CAdES-BES) |

**Verifying** (offline chain validation to the national root, exit `0` VALID / `1` INVALID / `2` INDETERMINATE):

| Command | Description |
|---|---|
| `verify` | Verify any signed file, auto-detecting PDF / XML / `.p7s` |
| `verify-pdf` / `verify-xml` / `verify-any` | Format-specific verification |

**Card and identity** (no PIN required):

| Command | Description |
|---|---|
| `fetch-identity` | Read the cardholder's biographical data over PC/SC |
| `fetch-photo` | Save the cardholder's photo (to a file, a stream, or a JSON record) |
| `validate-ci` | Validate (or complete) a cédula's check digit, offline, with no card |
| `list-readers` | List the available PC/SC smart card readers |
| `list-tokens` | List the PKCS#11 tokens in the library |
| `list-certs` | List the certificates on the card (`--pem` / `--json`) |

**Setup and maintenance:**

| Command | Description |
|---|---|
| `doctor` | Diagnose the local environment (pcscd, PKCS#11 module, card, CAs). `--native` checks the PC/SC path native signing uses |
| `fetch-cas` | Optional: re-fetch the currently pinned national CA certificates into a per-user cache. A rotated CA needs a new release, or `--ca-file` |

## Use as a library

Everything the CLI does is also a public Python API, `firmauy.api`, built on the same engine. It
returns frozen dataclasses and raises typed errors, never printed text or exit codes, so a GUI or
a script can consume it directly:

```python
import getpass
from firmauy.api import sign, verify

report = sign("contract.pdf", pin_provider=lambda: getpass.getpass("PIN: "))
print(report.kind, "->", report.output_path)   # pades -> contract_firmado.pdf

print(verify(report.output_path).indication)   # VALID
```

The `pin_provider` callback runs only after the reader, card and certificate check out, so a broken
setup never costs a PIN try. The native path (the API default, `--native` on the CLI) reads the
certificate from the card. The PKCS#11 path (the CLI default) reads what the token shows without
login, which on the cédula includes the signing certificate, and pairs it with its private key after
login, so a certificate without a key still shows up only after the PIN. Both refuse, before the PIN
is even asked for, to spend the card's last PIN try: native reads the card's counter, PKCS#11 relies
on the module reporting it (OpenSC does). Domain conditions raise typed exceptions: a wrong PIN is
`IncorrectPinError` (carrying `attempts_remaining` on the native path), a locked card is
`PinLockedError`, that last-try refusal is `PinLastTryError`, an existing output is
`OutputExistsError`, and so on.

The full surface (every signature format, whole batches in one card session, reading the cédula's
identity and photo, listing readers, tokens and certificates, diagnostics, check-digit validation)
is documented in **[docs/api.md](docs/api.md)**.

## Documentation

- **[Usage guide](docs/usage.md)**: step-by-step examples for every command.
- **[Cookbook](docs/cookbook.md)**: task-oriented recipes for signing, verifying, privacy, automation and `jq` pipelines.
- **[Trust anchors](docs/trust-anchors.md)**: the bundled national CA certificates, how trust is pinned and refreshed, and the state of revocation.
- **[Card protocol reference](docs/card-protocol.md)**: the cédula's data model and the APDU-level signing protocol behind `--native` (native, PKCS#11-free signing).
- **[OpenSC backend](docs/opensc-backend.md)**: build OpenSC from source and sign through the fully open-source `opensc-pkcs11.so` module instead of the proprietary middleware.
- **[Library API](docs/api.md)**: the full `firmauy.api` reference: signing every format (single and batch), verification, reading the cédula, listing readers, tokens and certificates, diagnostics, and the typed reports and errors.
- **[Architecture](ARCHITECTURE.md)**: the layer boundaries and invariants: the presentation-free engine, the adapters on top, the PIN path and the error design.
- **[Development](docs/development.md)**: running from source with `uv`, the test suite, and developing without the card (SoftHSM2).

## Security considerations

- Never pass the PIN directly as a command-line argument.
- Prefer interactive PIN entry for manual use.
- From Python, prefer `pin_provider` over holding the PIN in a variable: it is requested only once
  the reader, card and certificate check out.
- For automation, prefer protected file descriptors or controlled environments.
- Review every document before signing it.
- Use batch signing only in trusted workflows.
- Keep your smart card, reader, PIN, and PKCS#11 middleware under your own control.
- Found a vulnerability? Report it privately: see [SECURITY.md](SECURITY.md).

## Privacy

This tool is designed to run entirely locally. The one recommended exception is deliberate and yours to take: cross-checking a signed document at firma.gub.uy uploads that document to a State-operated service.

It does not collect, transmit, or store any user data externally.

All cryptographic operations are performed on the user's machine and/or the connected smart card.

Note: Timestamping (`--tsa-url`) and revocation checking (`--check-revocation`) are optional and make network requests. Those go to public addresses only, with limits on redirects, size and time, and `--allow-private-network` admits an internal TSA or CRL/OCSP mirror. Details in [docs/usage.md](docs/usage.md#common-verification-options-and-output).

Note: the signing commands print a summary that includes identifying data (signer name, certificate issuer, certificate serial number and PKCS#11 key ID). This stays on your machine, but in batch or automated pipelines that output can end up in CI or centralized logs. Pass `--quiet` (`-q`) to the `sign-pdf`, `sign-pdf-batch`, `sign-xml`, `sign-xml-batch`, `sign-any` and `sign-any-batch` commands to suppress that block while still signing.

Note: `fetch-identity` reads and prints the cardholder's biographical data (names, birth date, birthplace, document number, MRZ), and `fetch-photo` outputs the cardholder's photo (to a file, a redirected stream, or a JSON record). This data is accessible from the card without PIN authentication, but it is still personal: pass `--redact` to `fetch-identity` to replace every field with `[REDACTED]` before sharing its output, use `fetch-photo --json --redact` for a metadata-only photo record, and treat any non-redacted output (file, redirected stream, or receiving application) as sensitive.

## Legal and compliance

This project is copyright-registered, experimental, community-maintained, and not officially certified.

It is intended for developers and technically proficient users who understand the implications of using smart cards, PKCS#11 middleware, and digital signatures.

**This project:**

- is **not affiliated with or endorsed by AGESIC**
- does **not** claim official certification or compliance
- does **not** guarantee the legal validity of generated signatures
- is provided **for technical and educational purposes**

While it uses standard cryptographic mechanisms and aims to align with Uruguayan digital signature practices, the generated signatures should not be assumed valid for legal or regulatory use without independent verification. Users are solely responsible for ensuring that generated signatures meet any legal or regulatory requirements applicable to their use case.

In practice that is one habit: every signed document that matters gets uploaded to
[firma.gub.uy](https://firma.gub.uy/) after signing, every time. The project keeps a public
record of agreement between its verdicts and the State validator's, and redacted result rows are
welcome: see the [conformance protocol](docs/security-invariants.md#the-conformance-protocol).

### Intended use

Local, developer-oriented signing and verification using a Uruguayan ID card through PKCS#11. It is especially aimed at users who want to:

- sign PDFs (PAdES), XML documents (XAdES), and arbitrary files (CAdES/.p7s) locally
- verify those signatures locally, including the certificate chain to the national root
- understand and reproduce a PKCS#11-based signing workflow
- experiment with smart card integration on Linux
- build automation around signing and verification under their own responsibility

It is **not** intended to replace official, certified, or legally guaranteed signing platforms.

### Scope

This tool focuses on technical integration with PKCS#11: signing (PDF/PAdES, XML/XAdES, files/CAdES) and local, standards-based verification, including certificate-chain validation to the Uruguayan national root. It aims for practical interoperability rather than strict compliance with any specific implementation.

It is **not** an official validator: it does not consult the official trust-service status list (TSL) or evaluate accreditation / qualified status, provide legal guarantees, or replace certified signing platforms.

For authoritative or legal verification, use AGESIC's official validator at [firma.gub.uy](https://firma.gub.uy/).

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

This registration concerns only the authorship of the software as a copyrighted work. It does **not** imply certification or legal validity. See [Legal and compliance](#legal-and-compliance).

## Development

The project uses [`uv`](https://docs.astral.sh/uv/). Clone, set up the environment and run the tests:

```bash
git clone https://github.com/carlosplanchon/firmauy.git
cd firmauy
uv sync
uv run pytest
```

The full workflow, the project layout, and developing without the card (SoftHSM2, since a wrong PIN can block the cédula) are in **[docs/development.md](docs/development.md)**.

## Contributing & reporting issues

Bug reports, questions, and pull requests are welcome.

Feel free to open an issue on GitHub. The contribution mechanics (including the required
[DCO](https://developercertificate.org/) sign-off, `git commit -s`) are in
**[CONTRIBUTING.md](CONTRIBUTING.md)**. For security problems, use the private channel described
in **[SECURITY.md](SECURITY.md)** instead of a public issue.

### Cookbook contributions welcome

Cookbook recipes (see **[docs/cookbook.md](docs/cookbook.md)**) are welcome, and one of the best ways
to help: they open the project to people who will not necessarily touch the PKCS#11, APDU or XAdES
internals but can still share real, useful workflows. A good recipe shows a real workflow with
minimal commands, the expected output, privacy notes, and the environment where it was tested.

Please do not include real names, document numbers, MRZ data, certificates, photos, or unredacted
verification output. Use `--redact` whenever sharing command output.

## Acknowledgements

- [@nicolasgutierrezdev](https://github.com/nicolasgutierrezdev): contributed the `fetch-identity` and `list-readers` commands for reading the cardholder's biographical data over PC/SC ([#1](https://github.com/carlosplanchon/firmauy/pull/1)). Also provided reference for the signature appearance inspired by signatures generated using the Uruguayan ID card (cédula), and helped test the XAdES (XML) signing feature.
- To Guadalupe Muses, a law student from Uruguay, for sharing valuable sources and perspectives on digital evidence, and for the conversations that helped shape the problem that eventually led to FirmaUY.

## License

This project is licensed under the Apache License 2.0.
