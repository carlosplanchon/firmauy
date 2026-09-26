# Using firmauy as a library

FirmaUY is a signing engine exposed through two surfaces: a command-line interface and this public
Python API. With `firmauy.api` you can sign, verify, read the cédula, introspect and diagnose from
your own program, without shelling out to the CLI. Every function returns plain dataclasses and
raises typed errors, never printed text or process exit codes, so the results are easy to consume.
This is the same API the desktop app is built on.

> **Status:** the API is young and may still evolve (1.7.0 renamed `verify_file` to `verify`, for
> instance), so pin the version you build on. The CLI's options are the older and more settled
> contract. As with the rest of FirmaUY, none of this is officially certified.

## Install

```bash
pip install firmauy      # or: uv add firmauy
```

Then import what you need:

```python
from firmauy.api import sign, verify, fetch_identity, run_doctor
```

## Verify a signature

`verify()` verifies a PDF, XAdES XML or detached CMS `.p7s`, auto-detecting the format. It needs
no card or PIN.

```python
from firmauy.api import verify

report = verify("contract.pdf")
print(report.indication)          # "VALID" / "INDETERMINATE" / "INVALID"
for sig in report.signatures:
    print(sig.signer, sig.trusted)
```

For a detached `.p7s`, pass the original file it signs. The default follows the
`<name>.p7s -> <name>` convention:

```python
report = verify("data.bin.p7s", original="data.bin")
```

Returns a `VerifyReport(indication, signatures)`, where each signature is a
`firmauy.verify_common.VerifyResult`.

`check_revocation=True` also fetches CRL and OCSP data, and any missing issuer certificate, and
fails the chain when the certificate is revoked or that data cannot be obtained. Those URLs come
from the certificates, so the fetches go to public addresses only, with caps on redirects, size and time (the
[outbound policy](usage.md#common-verification-options-and-output)). A refused fetch is named in
the chain check's `detail`. Pass `allow_private_network=True` to reach an internal CRL/OCSP mirror.

> **Changed in 1.18.0:** revocation fetches go through the outbound policy and no longer read
> `~/.netrc`. An internal mirror now needs `allow_private_network=True`.

### The signature timestamp

`sig.timestamp` is a `firmauy.verify_common.TimestampInfo` when the signature carries an RFC 3161
timestamp, and `None` when it does not. Read it rather than searching the check rows: the rows are
display, and their wording differs per format.

```python
ts = report.signatures[0].timestamp
if ts and ts.intact and ts.valid:
    print(ts.gen_time, ts.tsa_common_name)
```

| Field | Meaning |
|---|---|
| `present` | the signature carries a timestamp token |
| `intact` | the token is unmodified and its messageImprint binds it to this signature |
| `valid` | the TSA's signature over the token verifies |
| `trusted` | the TSA's certificate chained to an anchor supplied via `tsa_ca` |
| `gen_time` | the instant the TSA asserts, a `datetime` in UTC |
| `tsa_common_name` | the timestamping authority's common name, when the token names one |
| `detail` | why, when something is not `True` |

Three separate questions, and worth reading separately. A token can be perfectly sound and still
not chain to the anchors you passed, which says something about your `tsa_ca` and nothing about
the file. Only `trusted` depends on anchors; the other two are properties of the token itself and
are answered either way.

The flags are declared as `Optional[bool]`, where `None` means *not evaluated*: neither a pass nor
a failure. In practice `trusted` is the one that uses it, and it is `None` by default, whenever no
`tsa_ca` anchors were passed to `verify()`. Without anchors the chain is never looked at, so
reporting `False` would claim a check was made and failed. Treat `None` as "unknown" rather than as
falsy: `bool(None)` collapses "nobody looked" into "looked and it failed".

`gen_time` is reported whenever the token states one, including when the chain did not validate.
The date is the answer this object exists to carry, and losing it because the anchors were wrong
would throw away the part that was never in question.

A timestamp says *when* a signature existed, which is a separate question from whether the
signature is valid. A document can carry a sound signature and a broken timestamp, and that needs
two verdicts rather than one. A broken token holds the overall indication at `INDETERMINATE`.

The TSA's certificate is evaluated at `gen_time` rather than at verification time, so a stamp does
not decay when the responder certificate behind it expires. Without an archive timestamp this is
optimistic, knowingly: a self-asserted `gen_time` strictly needs independent proof the token
existed before that certificate expired, which is the AdES `-LTA` level and is not implemented.

### What a trusted timestamp buys the signature

Once the token itself is trusted, its `gen_time` also decides *when the signing certificate is
evaluated*. That is the point of a timestamp: a certificate expires and the signature it made does
not, and the stamp is the evidence that the signature already existed while the certificate was
still valid.

```python
report = verify("contract.pdf", ca_file="cas.pem", tsa_ca="tsa.pem")
# VALID even years after the signer's certificate expired, because the timestamp says when.
```

Only a **trusted** token moves it. Without `tsa_ca` the `gen_time` is a claim by a stranger, and
letting it choose the day the certificate is checked on would hand that choice to whoever could
alter the file. The chain check says which day it used, so a VALID result over an expired
certificate is never silent about why.

Combining this with `check_revocation=True` is the one combination that can be stricter than
either alone: revocation data is fetched now and then applied at the past moment, and a responder
that will not answer for a date years back fails the chain. Carrying revocation data from signing
time is the AdES `-LT` level, which firmauy does not produce.

> **Changed in 1.13.0:** PDF and detached CMS honour this. Only XAdES did, so the same file could
> come back VALID as XML and INDETERMINATE as PDF with nothing else different.

> **Changed in 1.12.0:** `timestamp` is new. Before it, PDF and detached CMS discarded the
> timestamp outcome entirely, so a broken token went unmentioned and the file could still come
> back `VALID`.
>
> **Changed in 1.12.1:** for XAdES, `intact` and `valid` used to be one boolean under two names,
> so a sound token under the wrong anchor reported `intact=False, valid=False` with no `gen_time`,
> which reads as a destroyed token rather than a mismatched anchor. That path also reported
> `valid=True` on the strength of the binding alone, without verifying the token's signature.

## Sign a file

`sign_file()` signs a file with the cédula, producing a detached CAdES-BES `.p7s`. The original file
is left untouched. It is the programmatic form of `sign-any`.

```python
import getpass
from firmauy.api import sign_file

report = sign_file("contract.pdf", getpass.getpass("Cédula PIN: "), native=True)
print(report.output_path)         # Path to the produced .p7s
print(report.signer)              # signer common name
```

The `pin` is supplied directly and stays in your process's memory, never in a command line or pipe.
It is verified only after the PIN-free certificate read, so a reader or card problem cannot spend a
card retry. **A wrong PIN still counts toward the card's retry limit and can block the cédula**, so
handle it with care.

- `native=True` (default) signs over PC/SC, the same path as `--native`. `reader` selects a reader.
- `native=False` uses a PKCS#11 module. `pkcs11_lib` is the module path (the bundled middleware by
  default, or e.g. OpenSC's `opensc-pkcs11.so`), `token_label` picks a token and `cert_id` pins the
  signing certificate.
- `output` overrides the default `<input>.p7s` path. `tsa_url` adds an RFC 3161 timestamp. The
  TSA has to be at a public address and must answer without a redirect. For an internal TSA, pass
  `allow_private_network=True`, which every signing function takes. *New in 1.18.0.*
- `verify=True` re-checks the fresh signature for integrity before returning.

Returns a `SignReport(output_path, signer, issuer, kind, backend, certificate_serial, verified,
pkcs11_lib)`: `kind` is the signature produced (`"pades"`, `"xades"` or `"cades"`, useful with
`sign()`'s auto-detection), `backend` is `"native"` or `"pkcs11"`, `pkcs11_lib` is the resolved
module path that signed in the PKCS#11 case (so you can tell the bundled middleware from OpenSC's
`opensc-pkcs11.so`; None in native mode), and `verified` is True when `verify=True` re-checked the
fresh signature. Raises on any error, such as an empty PIN, a missing input, an
existing output, or a card or PIN failure.

## Sign a PDF

`sign_pdf()` signs a PDF and returns a PAdES-signed PDF, with the signature embedded rather than
written to a separate `.p7s`. A visible appearance (signer, certificate serial and timestamp) is
stamped on the last page. For a PDF this is usually what you want instead of `sign_file`.

```python
import getpass
from firmauy.api import sign_pdf

report = sign_pdf("contract.pdf", getpass.getpass("Cédula PIN: "), native=True)
print(report.output_path)         # <name>_firmado.pdf by default
```

It takes the same PIN and backend options as `sign_file` (`native`/`reader` or
`pkcs11_lib`/`token_label`/`cert_id`). `reason` and `location` fill the PAdES signature metadata,
`tsa_url` adds an RFC 3161 timestamp, and `verify=True` re-checks the fresh signature for integrity
and whole-file coverage. Returns a `SignReport`.

### The visible stamp

`appearance` takes a `PdfAppearance` and decides where the stamp goes and what it says. It applies
to `sign_pdf()`, and to `sign()` and `sign_files()` when the resolved type is a PDF. Omit it and
you get exactly what firmauy has always drawn: the last page, a 205x70 box in the bottom-left
corner, all five lines, no image. *New in 1.16.0, with `corner` and `margin` in 1.17.0.*

```python
from firmauy.api import PdfAppearance, sign_pdf

# The default box can land on a footer or the last lines of text. This moves it.
sign_pdf("contract.pdf", pin, appearance=PdfAppearance(page=1, x1=320, y1=60, x2=560, y2=130))

# A logo behind the text, and a stamp that does not print the certificate serial.
sign_pdf("contract.pdf", pin, appearance=PdfAppearance(
    image="logo.png", image_mode="background", image_opacity=0.15, show_document=False))
```

| Field | Default | What it does |
|---|---|---|
| `page` | `-1` | Which page carries the stamp. `-1` is the last one. |
| `corner` | `None` | `"bottom-left"`, `"bottom-right"`, `"top-left"` or `"top-right"`, resolved against that page's real size. `None` uses the coordinates below as given. The values are the `StampCorner` enum, also importable from `firmauy.api`. |
| `margin` | `20` | Points between the stamp and the two page edges of `corner`. |
| `x1`, `y1`, `x2`, `y2` | `20, 20, 225, 90` | The box, in PDF points from the bottom-left of the page. With a `corner` set, only their size is used and the corner decides the place. |
| `image` | `None` | A PNG or JPEG to draw in the box. Checked when the appearance is built, so a file Pillow cannot decode raises `ValueError` there, before any card is touched. |
| `image_mode` | `"background"` | `background` (behind the text, faded), `side` (left of it), `only` (image, no text). The values are the `ImageMode` enum, also importable from `firmauy.api`. |
| `image_opacity` | `0.2` | How faded, in `background` mode. |
| `timezone` | `"America/Montevideo"` | The zone the printed date is rendered in. |
| `show_title` | `True` | "Firma electrónica avanzada, UY" |
| `show_signer` | `True` | "Firmado por: ..." |
| `show_document` | `True` | "Documento: ..." |
| `show_date` | `True` | "Fecha: ..." |
| `show_issuer` | `True` | The issuing authority's name. |

**Use `corner` rather than coordinates when you can.** A corner is resolved while the PDF is open,
against the MediaBox of the page that will carry the stamp, so it lands correctly whatever the
paper is. Absolute coordinates cannot: the default 205x70 box placed bottom-right of an A4 spans
x=370 to 575, and on an A5, which is 420 points wide, that hangs 156 points off the paper. Pages in
one file can differ, and `page=-1` with a corner reads the size of that last page rather than
assuming the first one's.

```python
from firmauy.api import PdfAppearance, StampCorner, sign_pdf

# Correct on A4, A5, Letter and anything else.
sign_pdf("contract.pdf", pin, appearance=PdfAppearance(corner="bottom-right"))
[member.value for member in StampCorner]   # ['bottom-left', 'bottom-right', 'top-left', 'top-right']
```

`corner="bottom-left"` with the default margin is exactly the box firmauy has always drawn, so
naming the corner it already used moves nothing. A box larger than the page raises rather than
drawing off the paper, and a margin wider than the space left over is clamped onto the page.

Two things worth knowing before you use it.

**The stamp is not the signature.** It is drawn on a page. Turning every line off, or replacing
the text with a logo, changes nothing about what is signed, what a verifier reads, or whether the
file validates. The signer, the issuer and the time live inside the signature, covered by the
cryptography, and `verify()` reads them from there.

**`show_document` is the certificate's serial, not the cédula number.** Other Uruguayan signing
software prints the national ID there. firmauy does not, on purpose: the serial identifies the
certificate just as precisely without putting somebody's document number on every copy of a file
they send out.

Values are validated when the `PdfAppearance` is constructed rather than during signing, so a bad
coordinate, an opacity outside 0 to 1, an unknown mode, an unknown time zone or a missing image
file all raise before the PIN is asked for and before the card spends one of its tries.

The same options are on the CLI, as `--corner` and `--margin`, and the five lines are
turned off with `--no-stamp-title`,
`--no-stamp-signer`, `--no-stamp-document`, `--no-stamp-date` and `--no-stamp-issuer`.

## Sign an XML

`sign_xml()` signs an XML and returns it with a XAdES-BES signature embedded (XAdES-T with
`tsa_url`). The output defaults to `<name>_firmado.xml`.

A document that already carries a signature over its whole content at the root is refused with a
`RuntimeError`. An enveloped signature covers the entire document, the existing signature
included, and under the XMLDSig enveloped transform every validator would then report the
existing one as no longer matching the document. Sign the signed XML as a detached CAdES with
`sign_file()` instead, which leaves it untouched, or sign the original unsigned document.

```python
from firmauy.api import sign_xml

report = sign_xml("factura.xml", pin, native=True)
print(report.output_path)
```

Same PIN and backend options as `sign_file`. Returns a `SignReport`.

## Sign any file (auto-detect)

`sign()` picks the signature type from the file content: a PDF is signed as PAdES, an XML as XAdES,
and anything else as a detached CAdES `.p7s`. This is the natural single entry point for a GUI
"Sign" button.

```python
from firmauy.api import sign

report = sign("document.pdf", pin, native=True)   # -> PAdES, document_firmado.pdf
```

Pass `sign_as="pdf"`, `"xml"` or `"cades"` to force a type instead of auto-detecting. `reason` and
`location` apply only when the resolved type is a PDF. Returns a `SignReport`.

The four accepted values are the `SignAs` enum, importable from `firmauy.api` alongside everything
else. Use it to build a menu, or to turn a bad value into your own message before the card is
touched, rather than hardcoding the strings or letting a `ValueError` surface from inside a signing
call:

```python
from firmauy.api import SignAs

[member.value for member in SignAs]     # ['auto', 'pdf', 'xml', 'cades']
SignAs("pkcs7")                         # ValueError, and no card was touched
```

It applies to `sign()`, `sign_files()` and `output_path_for()`, which all take `sign_as`.
*New in 1.15.0.*

## Sign several files in one session

`sign_files()` signs a list of files through a single card session, so the PIN is checked once for
the whole batch instead of once per file.

```python
from firmauy.api import sign_files

reports = sign_files(["a.pdf", "b.xml", "c.bin"], pin, native=True)
for r in reports:
    print(r.output_path)
```

Each file's type is resolved like `sign()`. `output_dir` writes the results there instead of next to
each input. Returns a list of `SignReport`.

`progress` is called after each input finishes, including any post-sign verification that was
asked for, with `(index, input_path, output_path)`, so a progress bar can be honest about what is
done. Finishing, not merely writing: an output whose self-check failed has been written and does
not reach the callback, for the same reason it is not in `completed`.

```python
sign_files(paths, pin, progress=lambda i, src, out: print(f"{i + 1}/{len(paths)}: {out.name}"))
```

It runs on the calling thread, inside the card session, so it should return quickly and must not
touch the card.

Fail-fast, but not silently. The first file that fails raises a `BatchSignError` carrying what was
already done:

```python
from firmauy.api import BatchSignError, sign_files

try:
    reports = sign_files(paths, pin)
except BatchSignError as exc:
    print(f"Signed {len(exc.completed)} of {len(paths)}, stopped at {exc.failed_path}")
    print(f"Reason: {exc.__cause__}")
    # exc.completed are real signatures, still on disk. Check .verified on each.
```

Those outputs are deliberately not rolled back: they are real signatures, and being able to say
"2 of 7 were signed" is worth a great deal more to the person waiting than "it failed".

`completed` is what is finished and can be handed to somebody. Since 1.14.0 it can include the file at
`failed_index`, whenever the failure came after that output was finished: `OutputCommittedError`,
where only the final permissions could not be set, and a callback raising after the signature was
written. So `len(completed)` is not always `failed_index`.

It is narrower than every file on disk: an output whose self-check failed, or whose self-check
could not be completed, has been written and is deliberately not here, because neither can be used
yet.

It is also narrower than "everything you do not have to redo", so **the work left over is not
`paths` minus `completed`**. A batch stops at one file, and what that file needs is in `__cause__`,
already structured: a `PostSignVerificationError` with `outcome="inconclusive"` says the output
exists and must not be signed again, only checked. Computing a retry list by subtraction would
sign it a second time.

A report being present says the output is finished rather than that it was checked. Read
`verified` per report.

`callback_error` holds what your own `progress` or `should_continue` raised, when one did.
Those run your code, and whatever they raise used to surface in place of everything else,
including the `OutputCommittedError` saying a file exists and must not be signed again. A broken
progress bar is not a reason to lose that, so it is carried here instead. *New in 1.14.0.*

`should_continue` is asked, before each file, whether to keep going. It is how a GUI offers a
Cancel button on a long batch:

```python
from firmauy.api import BatchSignCancelled, sign_files

try:
    reports = sign_files(paths, pin, should_continue=lambda: not stop_requested.is_set())
except BatchSignCancelled as exc:
    print(f"Stopped after {len(exc.completed)} files. They are signed and still there.")
```

It is only consulted **between** files. A signature is written whole or not at all, so a batch
stops at the next boundary rather than part-way through a document, and a batch of one large PDF
cannot be interrupted at all. That is the honest answer, and the one to show the person waiting.

`BatchSignCancelled` is deliberately not a `BatchSignError`: somebody pressing cancel is not the
batch breaking, and a caller reporting a failure should not catch it by accident. Both carry
`completed`, because both leave real signatures behind.

> **Changed in 1.11.0:** `should_continue` is new.

> **Changed in 1.10.0:** `progress` is new, and a partial batch now raises `BatchSignError`
> instead of letting the underlying error through with the completed work lost.

## Ask where the signature will be written

`output_path_for()` answers what `sign()` and `sign_files()` would name the output, without
signing anything. It needs no card and no PIN.

```python
from firmauy.api import output_path_for

output_path_for("contrato.pdf")                      # contrato_firmado.pdf
output_path_for("datos.bin")                         # datos.bin.p7s
output_path_for("contrato.pdf", sign_as="cades")     # contrato.pdf.p7s
output_path_for("a.bin", output_dir="firmados/")     # firmados/a.bin.p7s
```

An embedded signature (PDF, XML) keeps the input's extension and gets `_firmado` on the stem; a
detached one appends `.p7s` to the whole name, so the original name stays readable.

This is for warning about an existing output **before** asking for the PIN, in a GUI or a batch
script, rather than reimplementing the naming rule and having the copy drift. With the default
`sign_as="auto"` the file is read to detect its type, so it must exist; pass an explicit type to
ask about a file that is not there yet.

> **New in 1.10.0.**

## Diagnose the environment

`run_doctor()` runs the same checks as the `doctor` command and returns them as data, printing
nothing. It needs no card or PIN.

```python
from firmauy.api import run_doctor

report = run_doctor(native=True)
print(report.ok)                  # False if any check FAILed (a WARN does not fail)
for check in report.checks:
    print(check.status, check.name, check.detail)   # status: PASS / WARN / FAIL
```

`native=True` (default) checks the PC/SC reader and card that native signing uses. Set it False to
check the PKCS#11 middleware module at `pkcs11_lib` instead.

Returns a `DoctorReport(ok, checks)`, where each check is a
`DoctorCheck(status, name, detail, fix, sensitive)`.

`sensitive` marks a check whose `detail` can carry the cardholder's own data, so a consumer that
must not leak it (an MCP server handing results to a model, a log shipper) can decide without
parsing text:

```python
for check in run_doctor().checks:
    detail = "[REDACTED]" if check.sensitive else check.detail
    print(check.status, check.name, detail)
```

Today only the token-label check is marked, because some PKCS#11 modules use the holder's name for
it while others report a generic string, and the consumer cannot tell which. Every check carries the
key (in the API and in the CLI's `--json`), so a consumer can treat a missing one as sensitive and
fail closed.

## Read the cédula

`fetch_identity()` and `fetch_photo()` read the card over PC/SC. They need no PIN (the data is public)
and no signing session.

```python
from firmauy.api import fetch_identity, fetch_photo

person = fetch_identity()
print(person.given_names, person.lastnames, person.id_number)

photo = fetch_photo()
open("foto.jpg", "wb").write(photo.data)   # photo.data is the raw JPEG
```

`fetch_identity()` returns an `IdentityReport` (fields the card omits are `None`); `fetch_photo()`
returns a `PhotoReport` with the JPEG in `data`. Do not call these while a PKCS#11 signing session is
open on the same card.

## List readers, tokens and certificates

Introspection helpers, none of which need a PIN (unless a token hides its certificates behind a
login):

```python
from firmauy.api import list_readers, list_tokens, list_certs

list_readers()                       # ["ACS ACR 38U-CCID 00 00", ...]
list_tokens()                        # [TokenInfo(label=..., serial=...), ...]
list_certs(token_label="...")        # [CertInfo(id=..., subject={...}, ...), ...]
```

`list_readers()` returns the reader names (exactly what the `reader=` argument accepts).
`list_tokens()` and `list_certs()` take a `pkcs11_lib` (the bundled middleware by default);
`list_certs()` also accepts `token_label`, `cert_id`, an optional `pin` and `include_pem=True`.

## Validate a cédula number

`validate_ci()` checks a cédula number's check digit (a purely arithmetic consistency check, not an
identity or document check). `complete_ci()` appends the check digit to a body. Both need no card.

```python
from firmauy.api import validate_ci, complete_ci

validate_ci("1.234.567-8").valid    # True / False
complete_ci("1234567")              # body + its check digit
```

## Re-fetch the pinned national CA certificates

`fetch_cas()` downloads the national CAs (root + intermediate) into a per-user cache. Verification
already works offline with the bundled anchors, so this is optional.

It re-fetches *the certificates already pinned in this release*, and cannot take a new one: bytes
are accepted only when they match a fingerprint in the source, so an issuer rotation is rejected
by the same check that makes the download safe. Absorbing a rotation needs a new firmauy release,
or `ca_file=` at verification time. See
[trust-anchors.md](trust-anchors.md#validity-over-time).

```python
from firmauy.api import fetch_cas

bundle = fetch_cas()
print(bundle.root_path, bundle.intermediate_path)
```

## Errors

The domain conditions raise typed exceptions (importable from `firmauy.api` or `firmauy.errors`),
so a GUI or script can branch on what happened instead of matching message text:

```python
from firmauy.api import sign, IncorrectPinError, PinLockedError, CardNotFoundError

try:
    report = sign("contract.pdf", pin_provider=ask_pin)
except IncorrectPinError as exc:
    retry(attempts=exc.attempts_remaining)   # None when the backend cannot know (PKCS#11)
except PinLockedError:
    show_unblock_help()
except CardNotFoundError:
    ask_to_insert_card()
```

The hierarchy, under a common `FirmaUYError` base:

- `ReaderNotFoundError`, `CardNotFoundError`: no reader / reader present but no card.
- `PinError`: base for PIN problems, with `IncorrectPinError` (carries `attempts_remaining` on the
  native path) and `PinLockedError`.
- `CertificateError`: base, with `CertificateNotFoundError`, `CertificateNotValidError` (expired
  or not yet valid) and `SigningKeyNotFoundError`, plus `TokenNotFoundError` for the PKCS#11 module.
- `OutputExistsError`: the output file exists and `overwrite` was not passed (carries `path`).
  Also raised when a file appears at that path *while* the signature is being made, which the
  up-front check cannot see.
- `OutputAccessControlError`: replacing the output would have changed who can read it, and the
  signature was not written (carries `path`). A signature is published by replacing an inode, and
  the replacement carries the access control of whoever created it rather than of the file it
  replaces. What overwriting preserves is exactly four things: POSIX owner, POSIX group, the
  `0o777` permission bits and the POSIX access ACL. Deliberately not preserved, and reset to what
  a new file gets: `setuid`, `setgid` and the sticky bit, non-POSIX ACLs, SELinux labels,
  capabilities and every other `security.*` or `user.*` attribute. Transplanting those onto a
  document this library just produced is not something a signing call implies.

  Raised when any of the four cannot be read or cannot be restored, which usually means the output
  belongs to another user or group, and also when the output cannot be read at all: the four are
  read through one open descriptor so that they cannot describe two different files, and there is
  no opening a file you have no permission to read. `chmod u+r` it and sign again. In every case
  nothing is written and the existing file is left exactly as it was.

  The guarantee is that the four describe a single inode, not that they are an atomic snapshot of
  it. Against another process already entitled to rewrite that inode's access control, an ordinary
  concurrent change is caught by its timestamp, subject to the resolution of the filesystem
  storing it. POSIX offers no atomic read of `stat` and ACL together.

- `OutputCommittedError`: **a committed output is complete and should not be signed again.** A
  signature is written whole or not at all and a failure normally leaves nothing behind, so
  treating an exception as "no output" is right except here and for `PostSignVerificationError`
  below. Setting the final permissions is the
  last step and happens after the atomic commit, deliberately, so the document is never readable
  by anyone else until it is in place under its own name. If that step fails, the file at `path`
  is complete and its bytes are final, and its mode stayed `0600`. Carries `path`, `final_mode`
  (the mode it should have been given) and `errno`. Repair the mode rather than signing again.

  Note what it does *not* claim: that the output was verified. `verify=True` runs after the
  signing call returns, so when this is raised the verification step never ran. In a batch the
  file is counted as written, appears in `BatchSignError.completed` with `verified=False`, and the
  CLI prints `SIGNED` rather than `OK`, or `SIGNED (not verified)` when `--verify` was asked for,
  plus a `WARN` line. It counts toward `Signed: n/m`, the summary gains `Needing a chmod: n`, and
  the command exits non-zero: the document is signed, but it did not do everything it was asked
  to. It is a `FirmaUYError` and deliberately not an `OSError`, so a caller catching
  the domain family sees it and one catching environment failures does not.

  *New in 1.14.0.*

- `PostSignVerificationError`: signing with `verify=True` wrote the output and the check that
  should have confirmed it did not. A file exists at `path`. `outcome` says which of three
  situations it is, and two of the three say do not sign again:

  | `outcome` | what is known | what to do |
  |---|---|---|
  | `"failed"` | a self-contained signature, PDF or XAdES, is not intact. Nothing else it could be | delete it and sign again |
  | `"detached-mismatch"` | a `.p7s` does not verify against the file in `covers`. Either the signature is not intact or that file changed after signing, and this cannot tell which | find out which file was meant to be covered first. Re-signing would sign whatever it holds now |
  | `"inconclusive"` | the check could not run: the verifier raised, or the output could not be read back. Nothing is known | retry the verification, not the signing, which would add a second signature to a document whose first was never examined |

  `covers` is the file a detached signature is over, and `None` otherwise. None of the three is in
  `BatchSignError.completed`: all three leave something that cannot be handed to anybody. Was a
  bare `RuntimeError` before 1.14.0, or whatever the verifier happened to raise. *New in 1.14.0.*
- `DetachedOriginalRequiredError`: a detached `.p7s` was given to `verify()` with no original to
  check it against, and the `<x>.p7s -> <x>` sibling is missing. Carries `p7s_path` and `expected`,
  so a GUI can name the file it wants. The two files routinely travel separately by email, so this
  is a recoverable situation, not a programming error.
- `BatchSignError`: `sign_files()` stopped at one file. Carries `completed` (finished outputs,
  which can include the file at `failed_index`), `failed_index`, `failed_path`,
  `callback_error` for a `progress` or `should_continue` that raised, and the real failure as
  `__cause__`.
- `BatchSignCancelled`: `sign_files()` was asked to stop through `should_continue`, and did, at a
  file boundary. Carries `completed` and `stopped_before`. Not a `BatchSignError`, on purpose.

Catch `FirmaUYError` for the whole family. These classes deliberately do **not** inherit from the
built-in error types: environment problems (pcscd down, PKCS#11 module missing) stay plain
`RuntimeError` with actionable messages, and bad arguments stay `ValueError`, so catching an
unexpected failure never silently catches an expected domain condition too. Use `run_doctor()` to
diagnose the environment in a structured way.

> **Changed in 1.8.0:** the domain errors no longer inherit `RuntimeError`. Catch `FirmaUYError`
> or the specific classes instead of a broad `except RuntimeError`.

> **Changed in 1.10.0:** a detached `.p7s` with no original now raises `DetachedOriginalRequiredError`
> instead of a bare `ValueError`. It does **not** inherit `ValueError`, so an `except ValueError`
> that used to catch it no longer does. Catch the new class, or `FirmaUYError`.

## Notes

- The signing functions take the PIN as `pin` (a string) or as `pin_provider` (a zero-arg callable
  invoked only when the PIN is actually needed, i.e. after the card is confirmed present, so a GUI
  can prompt on demand). Exactly one of the two. For a terminal prompt, `getpass.getpass` keeps it
  off the screen.
- Every result is a dataclass: `VerifyReport`, `SignReport`, `DoctorReport`/`DoctorCheck`,
  `IdentityReport`, `PhotoReport`, `TokenInfo`, `CertInfo`, `CiReport`, `CaBundle`. The exception
  is `output_path_for()`, which returns a plain `Path`.
- They do blocking I/O against the card and filesystem, so run them off the UI thread in a GUI.
- Verifying and the pure utilities (`validate_ci`, `complete_ci`) need no card, so they are safe to
  call anywhere, including in tests.
