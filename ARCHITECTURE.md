# Architecture

FirmaUY is a signing engine with several presentation adapters on top. This document describes
the boundaries between those layers and the invariants that hold across them, the things the
code cannot say by itself. It is deliberately about what stays stable: module responsibilities
and rules, not function signatures.

If you only read one thing: the engine is presentation-free, the adapters own all presentation,
and dependencies point strictly downward.

## Bird's eye view

```text
adapters      firmauy.cli          Typer commands: parsing, prompts, colors, exit codes
              firmauy.pin          how the CLI obtains the PIN (--pin-source prompt/env/stdin/fd)
              (external)           FirmaUY Desktop (Qt), firmauy-mcp-inspect (read-only MCP)

facade        firmauy.api          plain functions with typed inputs, frozen dataclass results
                                   and typed domain errors. The stable programmatic contract.

engine        firmauy.signing      the card-signing sessions and per-format signers
              firmauy._shared      format detection, trust-anchor resolution, doctor checks
              verification         pdf_verify, xml_verify, cms_verify, verify_common
              card access          card_reader (PC/SC, public AIS data), native_card (APDU signing)
              PKCS#11              pkcs11_utils (module/token/certificate access)
              network              outbound (the TSA request and the revocation fetches),
                                   revocation_fetchers
              support              cms_sign, xml_sign, appearance, cert_utils, national_ca,
                                   ci, constants, errors
```

**The dependency rule**: arrows only point downward. The engine never imports the adapters or
the facade. `firmauy.api` and `firmauy.cli` both build on the same engine and never on each
other. A quick way to check the rule holds: nothing under the engine imports `typer`, `firmauy.cli`
or `firmauy.api`.

`firmauy.pin` belongs to the CLI layer even though it does not define commands: it implements
`--pin-source`, a terminal concern. The engine never sees it.

## The engine is presentation-free

These invariants hold for every engine module:

- It never prints, never prompts, never exits and never imports `typer`.
- Informational lines go through an optional `notify` callback (`Callable[[str], None]`). The
  CLI passes a stderr printer, the API passes nothing and the lines are dropped. Message
  convention: `Warning:` marks something actionable about this run, `Note:` marks standing
  advice. Errors are never delivered through `notify`, they are raised.
- The signing session yields a `_SigningContext` that carries the identity display fields
  (signer, issuer, certificate serial, token label or reader name). Printing the identity block
  is the caller's job, which is also where `--quiet` lives.
- Results returned by the facade are frozen dataclasses. Nothing returns printed text or exit
  codes.

## One signing session, two backends

`firmauy.signing._signing_session` is the heart of the engine. It dispatches to one of two
backends and yields the same context either way, so every consumer (all sign commands, the API,
batches) is backend-agnostic:

- **native**: PC/SC APDUs straight to the card via `native_card`, no PKCS#11 module involved.
- **pkcs11**: any PKCS#11 module via `pkcs11_utils`, the proprietary middleware and OpenSC's
  `opensc-pkcs11.so` alike.

The context exposes two lazy, memoized signer factories: a pyHanko `Signer` for PDF/CMS and a
raw bytes-to-bytes callable for XML. Laziness means an XML-only run never builds the PDF
machinery, and memoization means a batch reuses one signer for every file in the session.

### The PIN path

The PIN ordering is a safety invariant, not a style choice. A wrong PIN spends one of the card's
limited retries, so the session is arranged to make that as unlikely as possible:

1. Pre-flight checks run first, with no reader or PIN access (a hard error for `cert_id` with
   native, notes for options that do not apply).
2. What can be checked without a PIN is checked. The native path reads the signing certificate
   and rejects an expired or not-yet-valid one. The PKCS#11 path loads the module and finds the
   token, but chooses the certificate only after login, because pairing a certificate with its
   private key needs the PIN session. So a certificate problem surfaces before the PIN on the
   native path and after it on PKCS#11.
3. Only then is the PIN resolved: a direct `pin` string, or a lazy `pin_provider()` callback
   invoked at this exact point. The CLI wraps its whole `--pin-source` handling in one provider.
   A GUI can open its PIN dialog here, knowing the card is ready.
4. A PIN that is empty, not all digits, or not 4 to 8 digits long is refused before touching the
   card. On the native path, `verify_pin` probes the retry counter first and refuses to spend the
   last try. The PKCS#11 path has no such guard.

The PIN is never placed in argv, results, logs or exception messages.

## Errors

`firmauy.errors` defines a small hierarchy under `FirmaUYError` for the conditions a caller can
meaningfully branch on: reader/card presence, PIN outcomes (`IncorrectPinError` carries
`attempts_remaining` when the backend can know it), certificate problems and existing outputs.

Two deliberate rules:

- Every domain error also inherits the built-in the engine historically raised (`RuntimeError`),
  so broad handlers and older callers keep working. The PKCS#11 session translates the
  middleware's own PIN exceptions into these types, making both backends raise identically.
- Environment problems (pcscd down, PKCS#11 module missing, ambiguous reader choice) stay plain
  `RuntimeError` with actionable messages. `run_doctor` / `firmauy doctor` is the structured way
  to diagnose the environment, not the exception hierarchy.

## Trust

Verification is offline by default and needs no card. Trust anchors resolve in order: an explicit
CA file, else the per-user cached copy (refreshed by `fetch-cas`, pinned by fingerprint), else the
certificates bundled with the package. The details live in `docs/trust-anchors.md`.

Two requests go out to URLs that firmauy is handed rather than ones it knows: the revocation
fetches under `--check-revocation`, whose URLs come from the certificates a document carries, and
the TSA request under `--tsa-url`. Both go through `firmauy.outbound` and nothing else: public
destinations only (link-local never, loopback and private networks with
`--allow-private-network`), the name resolved once and the socket pinned to the vetted address,
limits on redirects, size and total time, and no `~/.netrc`. `revocation_fetchers` routes
pyhanko-certvalidator's fetchers through it. A new request of that kind belongs there too. The
exception is `fetch-cas`, which downloads from fixed official URLs and pins what it gets by
fingerprint.

## Testing strategy

The suite never touches a real cédula. A wrong PIN on the real card burns retries and can block
it, so:

- Unit tests build certificates in memory and fake the card connection.
- Integration tests provision throwaway SoftHSM2 tokens and drive the real PKCS#11 path end to
  end, including wrong-PIN cases, which are safe there.
- Only a human with the physical card validates the native APDU path, `fetch-identity`,
  `fetch-photo` and reader detection.

## The wider ecosystem

FirmaUY is the engine of a small family of projects around the Uruguayan cédula:

- The cédula driver in [OpenSC](https://github.com/OpenSC/OpenSC) (`card-cedulauy`), which makes
  the card work through a fully open-source PKCS#11 module. FirmaUY consumes it like any other
  module.
- FirmaUY Desktop, a Qt application for non-technical users. It imports `firmauy.api` in
  process, which is why the facade returns data and never prints.
- `firmauy-mcp-inspect`, a read-only MCP adapter for AI assistants. It deliberately gets no
  signing capability, an authority boundary rather than a technical one. It is the one consumer
  that should **not** import `firmauy.api`: it runs the CLI as a subprocess, so signing and
  cardholder-data reading are absent from its process rather than merely uncalled.

## Where to start reading

- `src/firmauy/api.py` for the public surface and its dataclasses.
- `src/firmauy/signing.py` for the session, the two backends and the PIN path.
- `src/firmauy/cli.py` for how an adapter presents the same engine.
- `docs/api.md` for the consumer-facing reference of everything above.
