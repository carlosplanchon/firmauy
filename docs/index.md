# FirmaUY

**Your cédula is a signing key. FirmaUY brings it to the terminal.**

FirmaUY signs and verifies PDF, XML and arbitrary files with the Uruguayan national ID card
(cédula) over PKCS#11 or, optionally, PC/SC. It produces open-standard signatures (PAdES, XAdES,
CAdES) and checks the whole trust chain locally against the Uruguayan national root. Documents stay
on your machine.

Use it from the terminal, or from Python through the public API.

!!! warning "Unofficial and experimental"
    FirmaUY performs local, technical signing and verification. It is not affiliated with AGESIC,
    is not officially certified, and does not guarantee legal validity. Use the official validator
    at <https://firma.gub.uy/> for legal or administrative purposes.

!!! tip "Always cross-check what you sign"
    Before sending or relying on a signed document, upload it to <https://firma.gub.uy/> and keep
    the answer. firmauy checking its own output is not independent evidence. Uploading sends the
    document to a State-operated service, so handle confidential material accordingly. A detached
    `.p7s` cannot be checked there.

## Quick start

Requirements: Linux or Windows (x64), a smart-card reader, and either the cédula PKCS#11 middleware
or the native PC/SC backend.

```bash
uv tool install firmauy          # install the CLI in an isolated environment
firmauy doctor                   # check the smart-card setup, the module and the card
firmauy list-tokens              # confirm the card is detected
firmauy sign-pdf input.pdf       # sign; prompts for the PIN without echoing it
firmauy verify input_firmado.pdf # verify locally, including the chain
```

Then upload `input_firmado.pdf` at <https://firma.gub.uy/>.

New to the tool? Read [Setup](setup.md) first, then the [Usage guide](usage.md).

## What it does

| Format | Command | Output | Verification | Timestamp |
|---|---|---|---|---|
| PDF / PAdES | `sign-pdf` | signed `.pdf` | `verify-pdf` or `verify` | optional, external TSA |
| XML / XAdES | `sign-xml` | signed `.xml` | `verify-xml` or `verify` | optional, external TSA |
| Any file / CAdES | `sign-any` | detached `.p7s` | `verify-any` or `verify` | optional, external TSA |

Each command has a batch variant (`sign-pdf-batch`, `sign-xml-batch`, `sign-any-batch`) and the
mixed `sign` / `sign-batch` commands. The default PDF signature has a visible appearance modelled on
documents signed with the cédula.

The card can also be read without a PIN:

| Command | What it reads |
|---|---|
| `fetch-identity` | Names, birth date, birthplace, document number and MRZ |
| `fetch-photo` | The cardholder's JPEG photo |
| `list-readers` | PC/SC readers |
| `list-tokens` / `list-certs` | PKCS#11 tokens and certificates |
| `validate-ci` | Offline check digit validation |
| `doctor` | Setup diagnostics |

## Where the key lives

The private key is generated at card issuance, stored in the cédula's secure element, and never
leaves it. firmauy has no key import, export, backup or recovery operation. It asks the card to
sign and receives a signature. The PIN unlocks that operation and is never stored.

Read [Security and keys](https://github.com/carlosplanchon/firmauy/blob/main/docs/security.md) for
the full model: PIN retry protection, trust anchors, atomic output files, input limits, the outbound
network policy and the non-goals.

## Documentation

- [Setup](setup.md): operating systems, middleware, installation, first run and troubleshooting.
- [Usage guide](usage.md): every command, option and output.
- [Cookbook](cookbook.md): recipes for privacy, automation and pipelines.
- [Security and keys](https://github.com/carlosplanchon/firmauy/blob/main/docs/security.md): how
  security is enforced and what it does not cover.
- [Trust anchors](trust-anchors.md): the bundled national CAs and how they are pinned.
- [Card protocol](card-protocol.md): the APDUs behind native signing.
- [Library API](api.md): the typed Python API.
- [Security invariants](security-invariants.md): the timestamp verification evidence.
- [Development](development.md): run from source and test without a card.

## Use as a library

```python
import getpass
from firmauy.api import sign, verify

report = sign("contract.pdf", pin_provider=lambda: getpass.getpass("PIN: "))
print(report.kind, "->", report.output_path)
print(verify(report.output_path).indication)
```

`pin_provider` runs only after the reader, card and certificate checks pass, so a broken setup never
costs a PIN try.

## Privacy

FirmaUY runs locally. Signing and verification do not send documents anywhere. The optional
`--tsa-url` and `--check-revocation` features make outbound requests to public addresses only, with
size, time and redirect limits. The one recommended upload is the cross-check at
<https://firma.gub.uy/>, and it is your choice.

Identity and photo output is personal data. Use `--redact` before sharing it, and pass `--quiet` to
signing commands in automated logs to suppress the signer block.
