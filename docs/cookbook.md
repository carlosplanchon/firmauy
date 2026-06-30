# FirmaUY cookbook

Practical, copy-pasteable recipes for real workflows. The [README](../README.md) explains **what**
each command does; this cookbook shows **how** to combine them in everyday use, automation and
debugging.

> **Privacy first.** The cédula exposes the cardholder's personal data (names, document number, MRZ,
> photo). Every example here uses fictitious values, and any recipe that shares output uses
> `--redact`. Never paste real names, document numbers, MRZ data, certificates, photos or unredacted
> verification output into issues, logs or screenshots.
>
> Exit codes for the `verify*` commands are `0` VALID, `1` INVALID, `2` INDETERMINATE, so they slot
> straight into shell conditionals and CI.

## Basics

Diagnose the environment (no card or PIN needed for the setup checks):

```bash
firmauy doctor                 # human-readable setup report (pcscd, PKCS#11 module, card, CAs)
firmauy doctor --json-pretty   # same, machine-readable
```

Sign a PDF and verify it immediately (the `--verify` sanity check runs right after signing):

```bash
firmauy sign-pdf contrato.pdf --verify     # -> contrato_firmado.pdf, then checks it
firmauy verify contrato_firmado.pdf        # full verification (auto-detects the format)
```

Scriptable verification with `jq` (read just the indication):

```bash
firmauy verify contrato_firmado.pdf --json | jq -r .indication   # -> VALID
```

## Cédula numbers (check digit, no card)

Validate a cédula's check digit (a purely arithmetic consistency check; not an identity or document
validity check). It needs no card, PIN or network, so it works anywhere:

```bash
firmauy validate-ci 1.234.567-2     # -> VALID    (exit 0)
firmauy validate-ci 12345678        # -> INVALID  (exit 1)
```

Use it as a guard in a script (exit `0` valid, `1` invalid, `2` malformed input):

```bash
for ci in "$@"; do
  firmauy validate-ci "$ci" >/dev/null && echo "$ci ok" || echo "$ci REJECTED"
done
```

Complete a body that is missing its check digit (the "calculator" mode):

```bash
firmauy validate-ci 1234567 --complete    # -> 12345672
```

## Privacy and debugging

Share a verification result without any personal data:

```bash
firmauy verify contrato_firmado.pdf --json-pretty --redact
firmauy fetch-identity --json-pretty --redact
firmauy fetch-photo --json-pretty --redact
```

The redacted photo record carries no image and no fingerprint, only the (constant) shape of the file:

```json
{ "schema_version": 1, "redacted": true, "format": "jpeg", "mime": "image/jpeg", "width": 240, "height": 320 }
```

Build a debug report that is safe to attach to a GitHub issue (every block is redacted or PII-free):

```bash
{
  echo "### doctor";        firmauy doctor --json-pretty
  echo "### certificates";  firmauy list-certs --json-pretty --redact
  echo "### verification";  firmauy verify contrato_firmado.pdf --json-pretty --redact
} > firmauy-debug.txt
```

(It is a labelled text report, not a single JSON document, since it concatenates several outputs.)

## Unix-friendly

View the photo without ever writing a file (pipe the raw JPEG to any viewer that reads stdin):

```bash
firmauy fetch-photo - | feh -        # or: firmauy fetch-photo - | display
```

Save the photo to a file:

```bash
firmauy fetch-photo cedula_foto.jpg
```

Pull just the non-identifying metadata (dimensions) out of the JSON record:

```bash
firmauy fetch-photo --json --redact | jq '{width, height}'
```

Reconstruct the image from the full JSON record (note: `base64` is the actual photo, personal data):

```bash
firmauy fetch-photo --json | jq -r .base64 | base64 -d > cedula_foto.jpg
```

## Automation

Batch-sign a whole folder with a single PKCS#11 session, re-verifying each result:

```bash
firmauy sign-pdf-batch --input-dir docs --output-dir signed --verify
```

Fail a pipeline when a signature is not valid (the exit code already encodes the indication, so no
parsing is needed):

```bash
firmauy verify contrato_firmado.pdf || { echo "signature not VALID"; exit 1; }
```

If you prefer to branch on the indication explicitly:

```bash
# --redact keeps result.json free of signer PII; the indication is identical with or without it
firmauy verify contrato_firmado.pdf --json --redact > result.json
test "$(jq -r .indication result.json)" = "VALID"
```

Feed the PIN from a file descriptor (keeps it out of argv, env and shell history):

```bash
firmauy sign-pdf contrato.pdf --pin-source fd --pin-fd 3 3< pin.txt
```

`pin.txt` holds your PIN: keep it out of version control and delete it when done. See the
[PIN sources](../README.md#non-interactive-pin) table for the trade-offs between `prompt`, `fd`,
`stdin` and `env`.

## AdES formats

Sign without thinking about the format: `sign` picks PAdES / XAdES / detached CAdES from the file:

```bash
firmauy sign contrato.pdf --verify    # PDF -> PAdES
firmauy sign factura.xml --verify     # XML -> XAdES
firmauy sign payload.zip --verify     # anything else -> detached .p7s
```

Sign a whole mixed folder (PDFs, XMLs, anything) in a single PKCS#11 session, with one PIN prompt:

```bash
firmauy sign-batch --input-dir contracts --output-dir signed --recursive --verify
```

Sign an XML document (XAdES), then verify it:

```bash
firmauy sign-xml factura.xml --verify
firmauy verify factura_firmado.xml
```

Sign any file with a detached CAdES `.p7s` (the original is left untouched):

```bash
firmauy sign-any payload.zip          # -> payload.zip.p7s
firmauy verify-any payload.zip        # finds payload.zip.p7s next to it
```

Add an RFC 3161 timestamp (bring your own TSA; optional, not part of the standard cédula flow):

```bash
firmauy sign-any contrato.zip --tsa-url https://your-tsa/endpoint
```

---

## Contributing recipes

Cookbook recipes are very welcome, and a great first contribution that does not require touching the
PKCS#11, APDU or XAdES internals. A good recipe shows a real workflow with minimal commands, the
expected output, any privacy notes, and the environment where it was tested.

Please do not include real names, document numbers, MRZ data, certificates, photos or unredacted
verification output. Use `--redact` whenever a recipe shares command output. See
[Contributing](../README.md#contributing--reporting-issues).
