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

## Contents

- [Basics](#basics)
- [Signing (all formats)](#signing-all-formats)
- [Verification and audit](#verification-and-audit)
- [Cédula numbers (check digit, no card)](#cédula-numbers-check-digit-no-card)
- [Privacy and debugging](#privacy-and-debugging)
- [The cardholder's photo](#the-cardholders-photo)
- [Automation](#automation)
- [Nushell](#nushell)
- [Contributing recipes](#contributing-recipes)

## Basics

Diagnose the environment (no card or PIN needed for the setup checks):

```bash
firmauy doctor                 # human-readable setup report (pcscd, PKCS#11 module, card, CAs)
firmauy doctor --json-pretty   # same, machine-readable
```

Sign a PDF and verify it immediately (the `--verify` sanity check runs right after signing):

```bash
firmauy sign-pdf documento.pdf --verify     # -> documento_firmado.pdf, then checks it
firmauy verify documento_firmado.pdf        # full verification (auto-detects the format)
```

Scriptable verification with `jq` (read just the indication):

```bash
firmauy verify documento_firmado.pdf --json | jq -r .indication   # -> VALID
```

## Signing (all formats)

Sign without thinking about the format: `sign` picks PAdES / XAdES / detached CAdES from the file:

```bash
firmauy sign documento.pdf --verify    # PDF -> PAdES
firmauy sign documento.xml --verify   # XML -> XAdES
firmauy sign archivo.zip --verify     # anything else -> detached .p7s
```

Sign a whole mixed folder (PDFs, XMLs, anything) in a single PKCS#11 session, with one PIN prompt:

```bash
firmauy sign-batch --input-dir documentos --output-dir signed --recursive --verify
```

For one file type, use the per-type batch commands `sign-pdf-batch`, `sign-xml-batch` and
`sign-any-batch` (same single-session, one-PIN behavior, re-verifying each result with `--verify`):

```bash
firmauy sign-pdf-batch --input-dir docs --output-dir signed --verify
```

Sign an XML document (XAdES), then verify it:

```bash
firmauy sign-xml documento.xml --verify
firmauy verify documento_firmado.xml
```

Sign any file with a detached CAdES `.p7s` (the original is left untouched):

```bash
firmauy sign-any archivo.zip          # -> archivo.zip.p7s
firmauy verify-any archivo.zip        # finds archivo.zip.p7s next to it
```

Add an RFC 3161 timestamp (bring your own TSA; optional, not part of the standard cédula flow):

```bash
firmauy sign-any archivo.zip --tsa-url https://your-tsa/endpoint
```

## Verification and audit

FirmaUY verifies signed documents **locally and offline**, checking the certificate chain to the
Uruguayan national root with no card and no PIN. This is a **technical** check, and by default it does
not include revocation: a VALID result means the signature is intact and chains to the national root,
not that the certificate was never revoked (revocation is opt-in, see
[Trust anchors](trust-anchors.md)). For authoritative or legal validation, use the official validator
at [firma.gub.uy](https://firma.gub.uy/). `--json` adds a
machine-readable breakdown, and in Nushell you wrap the call in `complete` so a non-VALID result
(which exits `1` or `2`) does not abort the pipeline (see [Nushell](#nushell)).

Verify a document someone sent you, without the card. The same works for XML and detached `.p7s`.
FirmaUY anchors trust to the Uruguayan national root, so a signature issued under a foreign PKI is
reported INDETERMINATE (integrity checked, trust not established) unless you supply its root with
`--ca-file`:

```bash
firmauy verify documento_recibido.pdf                          # human-readable, exit code = verdict
firmauy verify documento.pdf --json-pretty --redact     # full detail, signer PII hidden
```

```nu
# just the verdict
firmauy verify documento_recibido.pdf --json | complete | get stdout | from json | get indication   # -> VALID

# per-signature detail as a table (a single PDF can carry several signatures)
firmauy verify documento_recibido.pdf --json --redact | complete | get stdout | from json | get signatures | select indication trusted
```

Turn a whole inbox of signed PDFs into one audit report, with no PIN and no card involved. `--redact`
keeps signer personal data out of the report:

```bash
echo "file,indication" > audit.csv
find inbox -name '*.pdf' | while read -r f; do
  echo "$f,$(firmauy verify "$f" --json --redact | jq -r .indication)" >> audit.csv
done
```

```nu
let report = (ls inbox/**/*.pdf | get name | each {|f|
  {file: $f, indication: (firmauy verify $f --json --redact | complete | get stdout | from json | get indication)}
})
$report | save --force audit.csv
$report | group-by indication | items {|k v| {verdict: $k, count: ($v | length)} }   # -> VALID 42 / INVALID 1 / ...
```

Inventory the signer and issuer of every signature. These commands show the signer names, which are
personal data, so add `--redact` before sharing to hide the signer's fields and keep only the issuer.
A signer name is a verified identity only when that row's verdict is VALID:

```bash
firmauy verify documento_firmado.pdf --json | jq '.signatures[] | {signer: .signer.common_name, issuer: .issuer.common_name, indication}'
```

```nu
ls firmados/*.pdf | get name | each {|f|
  firmauy verify $f --json | complete | get stdout | from json | get signatures | each {|s|
    {file: ($f | path basename), signer: $s.signer.common_name, issuer: $s.issuer.common_name, verdict: $s.indication}
  }
} | flatten
```

Gate a folder before you archive or send it, failing loudly if any document is not VALID so a bad
signature never slips into a bundle:

```bash
find outbox -name '*.pdf' -print0 | while IFS= read -r -d '' f; do
  firmauy verify "$f" >/dev/null || { echo "NOT VALID: $f"; exit 1; }
done
```

```nu
let bad = (ls outbox/**/*.pdf | get name | where {|f|
  (firmauy verify $f --json | complete | get stdout | from json | get indication) != "VALID"
})
if ($bad | is-not-empty) { error make {msg: $"not VALID: ($bad | str join ', ')"} } else { print "all VALID" }
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
firmauy verify documento_firmado.pdf --json-pretty --redact
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
  echo "### verification";  firmauy verify documento_firmado.pdf --json-pretty --redact
} > firmauy-debug.txt
```

(It is a labelled text report, not a single JSON document, since it concatenates several outputs.)

## The cardholder's photo

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

Wiring `verify` into scripts and CI. To batch-sign a folder in one session, see
[Signing (all formats)](#signing-all-formats).

Fail a pipeline when a signature is not valid (the exit code already encodes the indication, so no
parsing is needed):

```bash
firmauy verify documento_firmado.pdf || { echo "signature not VALID"; exit 1; }
```

If you prefer to branch on the indication explicitly:

```bash
# --redact keeps result.json free of signer PII; the indication is identical with or without it
firmauy verify documento_firmado.pdf --json --redact > result.json
test "$(jq -r .indication result.json)" = "VALID"
```

Feed the PIN from a file descriptor (keeps it out of argv, env and shell history):

```bash
firmauy sign-pdf documento.pdf --pin-source fd --pin-fd 3 3< pin.txt
```

`pin.txt` holds your PIN: keep it out of version control and delete it when done. See the
[PIN sources](../README.md#non-interactive-pin) table for the trade-offs between `prompt`, `fd`,
`stdin` and `env`.

> ⚠️ **A wrong PIN in automation can lock the cédula.** Each incorrect attempt counts toward the
> card's retry limit, and a bad PIN in a script is re-sent on every run, so double-check it before
> unattended use. `--native` refuses to spend the card's last try. The default PKCS#11 path does
> not, and firmauy cannot unblock a locked PIN.

## Nushell

[Nushell](https://www.nushell.sh/) parses firmauy's JSON straight into structured tables, which is
handy for the nested `verify` output (a `signatures` list, each with its own `checks`). One thing to
know first: nushell treats any non-zero exit code from an external command as an error that aborts
the pipeline, and the `verify*` commands deliberately exit `1` (INVALID) and `2` (INDETERMINATE). A
plain pipe such as `firmauy verify documento_firmado.pdf --json | from json` therefore breaks on
exactly the failing cases. Wrap the call in
[`complete`](https://www.nushell.sh/commands/docs/complete.html), which captures `stdout`, `stderr`
and `exit_code` into a record without aborting. The recipes below were tested with `nu 0.113.1`.

The [Verification and audit](#verification-and-audit) recipes already show the core verify and gate
workflows in nushell, so the ones here focus on what nushell adds on top of `jq`.

Keep the exit code alongside the verdict (firmauy also carries the verdict in `indication`, so you
can read the field instead of the code):

```nu
let r = (firmauy verify documento_firmado.pdf --json | complete)
$r.exit_code                              # -> 0 VALID / 1 INVALID / 2 INDETERMINATE
$r.stdout | from json | get indication    # -> VALID / INVALID / INDETERMINATE
```

List the failing checks across every signature as a table (where nushell's structured output beats
`jq`):

```nu
firmauy verify documento_firmado.pdf --json | complete | get stdout | from json | get signatures
  | each {|s| $s.checks} | flatten | where ok == false
```

Pull the non-identifying photo dimensions out of the JSON record:

```nu
firmauy fetch-photo --json --redact | complete | get stdout | from json | select width height
```

Browse the card's certificates as a table (add `--redact` before sharing the output):

```nu
firmauy list-certs --json | complete | get stdout | from json
```

---

## Contributing recipes

Cookbook recipes are very welcome, and a great first contribution that does not require touching the
PKCS#11, APDU or XAdES internals. A good recipe shows a real workflow with minimal commands, the
expected output, any privacy notes, and the environment where it was tested.

Please do not include real names, document numbers, MRZ data, certificates, photos or unredacted
verification output. Use `--redact` whenever a recipe shares command output. See
[Contributing](../README.md#contributing--reporting-issues).
