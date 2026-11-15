# Security and key handling

This page explains how firmauy protects the signing key, the PIN and the documents it handles, and
which threats are outside its control. It is written for operators, integrators and reviewers who
need to decide whether the tool is appropriate for their use.

The short version: **the private key never leaves the cédula**. firmauy has no key import, no key
export and no key generation. It asks the card to sign, and the card returns a signature. The PIN
is used only to unlock that operation, is never stored, and is checked before it is sent so that a
typo does not spend one of the card's few retries.

## Assets and boundaries

| Asset | Where it lives | Who can read it | firmauy's role |
|---|---|---|---|
| RSA private key | Inside the cédula secure element | The card only | Never reads it; asks the card to sign |
| PIN | The cardholder's memory; briefly process memory | The cardholder | Prompts, validates, sends once, discards |
| Signing certificate | Public, on the card (PKCS#11 object or EF B001) | Anyone | Reads it to display the signer and to validate it |
| Documents to sign | Local filesystem | The invoking user | Reads, signs, writes next to the input |
| Trust anchors | Bundled public certificates, pinned by SHA-256 | Anyone | Uses them to verify chains |
| Identity data and photo | Public AIS files on the card | Anyone with the card | Reads only when the user asks; redaction available |

There are four boundaries, and each one has a different enforcement mechanism:

1. **Cryptographic boundary.** The RSA private key is generated at card issuance and marked
   non-extractable by the card. Signing is a command sent to the card; the host receives only the
   signature. This is the property that matters most and the one firmauy cannot weaken.
2. **Process boundary.** firmauy runs as the invoking user, opens only the files it was asked to
   open, and writes only the output it was asked to write. It does not daemonize, listen on a
   socket, or run with elevated privileges.
3. **Operating system boundary.** File ownership, mode and ACLs on signed output are preserved where
   the platform supports them. Temporary files are created privately and committed atomically.
4. **Network boundary.** Signing and verification are offline by default. The only outbound requests
   are an RFC 3161 timestamp and revocation data, and only when the user asks for them.

## Key lifecycle

The key is created by the Uruguayan certification authority when the cédula is issued. It is stored
in the card's secure element and the card exposes only three operations to the host: present the
certificate, unlock signing with the User PIN, and sign a digest. The card does not expose the key
material to the PKCS#11 middleware, to the reader, or to firmauy.

firmauy enforces the boundary in three ways:

* **No key APIs.** The codebase contains no import, export, generation, backup or recovery operation
  for private keys. `list-certs` and `list-tokens` read public objects only. The PKCS#11 code looks
  up a key object by ID and hands it to pyHanko's `PKCS11Signer`; it never requests `CKA_VALUE` and
  never marks a key extractable.
* **No key in memory.** In native mode the host hashes the to-be-signed bytes and sends the digest
  to the card through `PSO:HASH`. The card builds the PKCS#1 DigestInfo and returns an RSA signature.
  The host never holds the key, not even decrypted, at any point.
* **No private key in output.** Signed PDF, XML and `.p7s` files contain the signature and the
  certificate chain, which are public, and never the key.

The counterpart of this design is that firmauy cannot recover a lost or blocked key. Unblocking the
PIN requires the PUK and the procedures of the issuing authority; firmauy does not handle the PUK.

## PIN handling

The PIN is the only secret the user supplies. Increasingly, it is also the asset most likely to be
lost by accident, because a cédula allows only a small number of wrong attempts before it blocks.

### Accepted sources

| Source | Option | Notes |
|---|---|---|
| Interactive prompt | `--pin-source prompt` (default) | Uses `getpass`, so the PIN is not echoed |
| Environment variable | `--pin-source env --pin-env-var NAME` | Convenient for automation; visible to the same user through the process environment |
| Standard input | `--pin-source stdin` | If stdin is a TTY, falls back to the hidden prompt; otherwise reads one line |
| Inherited file descriptor | `--pin-source fd --pin-fd N` | The recommended automation path; the PIN is not in `argv`, environment or shell history |

There is deliberately **no `--pin` option**. A PIN passed as a command-line argument would be
visible in the process list and the shell history, and would be captured by process accounting.

The Python API follows the same rule: pass `pin_provider=` (a zero-argument callable) rather than a
literal PIN. The provider is invoked only after the reader, certificate and PIN state checks pass.

### Validation before the card is touched

An incorrect PIN is not free: it consumes one retry. firmauy therefore rejects malformed input
before opening the token:

* An empty PIN is refused with the explanation that it would still count as an attempt.
* The PIN must be ASCII digits only and between 4 and 8 characters. Unicode digits that the card
  cannot accept (`٤`, `④`) are refused, and so are letters and whitespace.
* The PKCS#11 path validates `--cert-id` format before login.
* The certificate is checked for expiry and not-yet-valid dates before the PIN is requested.

### Retry counter protection

Both backends read the card's PIN state before asking for the PIN:

* **Native:** an empty `VERIFY` returns the remaining tries without consuming one. A blocked PIN,
  one try left, or an unreadable counter aborts before the prompt. The probe is repeated right
  before the PIN is sent, so `verify_pin` is safe even when called on its own.
* **PKCS#11:** the module's PIN flags are checked before login. Locked and last-try states are
  refused before the prompt.

A wrong PIN raises `IncorrectPinError` with `attempts_remaining` when the backend can know it. The
PIN itself never appears in an exception, a log line, a result object or a JSON record.

### Session lifetime

The PKCS#11 or PC/SC session is opened for the signing operation and closed in a `finally` block,
including when signing fails. The PIN is not cached between commands. A fresh process asks again.

## Signing backends

### PKCS#11 (default)

The module named by `--pkcs11-lib` is loaded from an explicit path. firmauy opens the token, reads the
public certificates, validates the selected certificate, logs in with the PIN and signs through the
module. The module and the card perform the private-key operation.

Trust in this path depends on the proprietary middleware. A compromised `libgclib.so` could, in
principle, do anything the process can do. Install it from a source you trust, keep it updated, and
prefer the distribution package or the AUR package named in the README. firmauy cannot audit a
binary middleware.

### Native PC/SC (`--native`, and the API default)

The native backend sends ISO 7816-4 APDUs directly to the card:

1. Select the AIS applet.
2. Read the public signing certificate from EF B001.
3. Probe the PIN retry counter.
4. Verify the PIN.
5. Select the signing key with `MSE:SET DST`.
6. Send the SHA-256 digest with `PSO:HASH`.
7. Read the RSA signature with `PSO:CDS`.

The signing certificate is checked before the PIN. The signature length is checked against the
RSA modulus size, so a truncated card response becomes an error instead of an invalid signature
embedded in a signed document. The protocol is documented in
[card-protocol.md](card-protocol.md).

Native mode removes the proprietary middleware from the trust base, leaving the card, the reader
firmware and the host as the components that must be trusted. It does not remove the card's own
security properties, and it does not make the key exportable.

## Verification and trust

Verification is local and offline by default. The chain is anchored to the Uruguayan national root
and the Ministerio del Interior intermediate, which are bundled as public certificates and pinned
by SHA-256. Every copy of those certificates, whether bundled, cached or downloaded, must match the
pin; the intermediate must also verify against the root. The origin of the bytes therefore does not
matter, and a tampered copy is rejected.

The operating system trust store is never consulted. With `--no-trust`, an explicit empty trust list
is used, so a signer whose chain reaches a root the operating system trusts is still reported as
untrusted. A validation result is one of:

* **VALID:** integrity holds and the chain reaches a trusted anchor.
* **INVALID:** integrity fails, or the chain is known to be untrusted or revoked.
* **INDETERMINATE:** integrity holds but trust could not be established or was not checked.

Revocation checking is off by default because it requires network access and a reachable CRL or
OCSP responder. When enabled, a fetch that fails, or a fetch that is refused by the outbound policy,
does not silently pass: the reason is reported in the chain rows.

Timestamp tokens are not trusted unless the user supplies TSA anchors with `--tsa-ca`. Without
them, the timestamp is reported as present but not trust-validated, and the document's own
`genTime` is not treated as a trusted signing time.

## Output files

Writing the signed file is a security-relevant step: a predictable temporary name or a symlink can
be turned into an overwrite of another file.

* **Staging is private and unpredictable.** The output is written to a fresh file created with
  `O_CREAT | O_EXCL` in the destination directory, with mode `0o600` where the platform supports
  it. The old predictable `<name>.part` is not used.
* **Commit is atomic.** The finished file is `fsync`ed and moved into place with `os.replace`, or
  with a hard link where the platform needs it. A reader never sees a half-written document.
* **Symlinks are not followed.** Existing output is opened with `O_NOFOLLOW` where available;
  Windows reparse points are detected before opening. A link planted at the output path is replaced,
  not followed.
* **Access control is preserved.** When replacing an existing regular file, its owner, group, mode
  and ACL (where supported) are copied onto the replacement. If that cannot be done, the command
  fails instead of producing a file with weaker permissions.
* **Existing files are not overwritten by default.** `--overwrite` is required, and the check is
  made before signing, so a refused output does not cost a PIN attempt.

On Windows, a signed file inherits the permissions of its folder and nothing is carried over from a
file it replaces. This is documented in the README.

## Input parsing and resource limits

A document is untrusted input. The parsers are given explicit limits and safe defaults:

| Input | Limit | Parser protection |
|---|---|---|
| XML (sign and verify) | 16 MiB | External entities disabled, network access disabled, no huge tree, no DTD loading |
| PDF (verify and post-sign check) | 128 MiB | Size checked before parsing; page-tree depth bounded |
| CMS / `.p7s` (verify) | 8 MiB | Size checked before parsing; trailing bytes tolerated only where the format allows |
| PDF image for the appearance | Decoded at the requested box size | Image decoding resources bounded; the image is checked before the PIN |
| TSA response | 4 MiB | Streamed with a hard byte limit and a time limit |

Files read in batch mode are confined to the input directory. A path that escapes it, including
through a symlink, is skipped and reported rather than signed.

## Network behavior

Signing and verification do not require a network connection. Two optional features do:

* `--tsa-url` sends the signature digest to an RFC 3161 timestamp authority.
* `--check-revocation` fetches CRLs, OCSP responses and issuer certificates named by certificates
  in the document or chain.

Both use one outbound policy:

* **Public destinations only by default.** Loopback, private and link-local addresses are refused.
  Link-local is refused even with `--allow-private-network`, because cloud metadata services answer
  there.
* **Resolved once.** The name is resolved, every address is judged, and the socket is opened to the
  address that was judged. DNS rebinding cannot swap in an internal address between the check and
  the connect.
* **Redirects are bounded and vetted.** The TSA request follows no redirects, because it can carry
  credentials. Revocation fetches follow at most three, and each destination is judged like the
  first.
* **Bounded.** Each request has a byte limit and a total time limit. A response that exceeds the
  limit is refused, not buffered without limit.
* **No ambient credentials.** `~/.netrc` is never read, so requests cannot silently send stored
  credentials to a host named by a document.

The URLs can come from an untrusted document or an untrusted certificate. That is why the defaults
are restrictive and why `--allow-private-network` is opt-in and named for what it does.

## Supply chain and release integrity

* Dependencies have security floors, not open ranges: `cryptography>=50.0.0`,
  `urllib3>=2.8.0`, `pyhanko>=0.35.1`, `lxml>=6.1.1` and so on. `urllib3` 2.8.0 is the first
  release that fixes three advisories on the response path that a malicious TSA or CRL server
  could reach.
* `uv.lock` pins the exact dependency graph for development and CI.
* CI runs lint, the test matrix (Linux and Windows, Python 3.11 to 3.14), the searching TSTInfo
  sweep and the deep property profile.
* The release workflow publishes with PyPI Trusted Publishing over OIDC. There is no long-lived
  PyPI token in the repository. The workflow runs in a protected `pypi` environment so a tag push
  can require manual approval, and it refuses to publish when the tag and the packaged version
  disagree.
* The bundled national CA certificates are public and pinned by SHA-256. Their provenance is in
  `src/firmauy/data/PROVENANCE.md`.

## Fail-closed behavior

The following conditions abort rather than guess:

| Condition | Behavior |
|---|---|
| PIN blocked or on its last try | No PIN prompt, no attempt spent |
| Retry counter unreadable | Refuse to send the PIN |
| Certificate expired or not yet valid | Refuse before the PIN |
| Certificate has no matching private key | Refuse before or during selection |
| Card returns a short signature | Error; no invalid signature is embedded |
| Output exists without `--overwrite` | Refuse before the PIN |
| Output permissions cannot be preserved | Refuse; do not write with weaker permissions |
| Input over its byte limit | Refuse before parsing |
| Network destination is not public | Refuse before connecting, unless explicitly allowed |
| Trust anchors are absent under `--no-trust` | Report untrusted; never fall back to the system store |
| TSA response over the limit | Refuse; do not parse a truncated response |

## What firmauy does not protect

Security claims are only useful when their limits are clear. firmauy does **not** protect against:

* A compromised host, a keylogger, a malicious shell, or an attacker who can read process memory
  while the PIN is being used.
* A compromised PKCS#11 middleware or a malicious card reader. Native mode removes the middleware
  from the trust base but still trusts the reader and the card.
* A stolen card with a known PIN. The card is the security boundary, and possession plus PIN is
  authorization.
* A malicious or backdoored TSA. Timestamps are only trusted when the user supplies TSA anchors.
* A malicious PDF or XML viewer that mishandles a correctly signed file.
* Legal validity, accreditation or certification. A VALID result is a technical assessment, not a
  legal one. Use the official validator at <https://firma.gub.uy/> for that purpose.
* The PUK, card unblocking, renewal or revocation of the cardholder's certificate.
* Confidentiality of documents after signing. firmauy does not encrypt documents and does not
  delete the originals.

## Secure usage checklist

1. Install from PyPI or from this repository, and keep the host, the reader stack and the PKCS#11
   middleware updated.
2. Prefer the hidden prompt for interactive use. In automation, prefer `--pin-source fd` over an
   environment variable, and avoid shell tracing around the command.
3. Run `firmauy doctor` before the first signing. It needs no PIN and catches most setup problems.
4. Sign a copy, verify it locally, and upload the result to the official validator when the
   document matters.
5. Keep `--check-revocation` off unless you have a reachable, trusted revocation source.
6. Supply `--tsa-ca` when you need a timestamp you can actually trust.
7. Use `--redact` when sharing `fetch-identity` or `fetch-photo` output.
8. Do not run two card operations in parallel on the same reader. PC/SC sessions conflict.
9. Treat signed files as sensitive. The signature protects integrity and origin, not
   confidentiality.
10. Review the trust anchors you pass with `--ca-file`. They are yours, and they are not pinned by
    firmauy.

## Standards and controls

| Area | Standard or practice | Where it is enforced |
|---|---|---|
| Card commands | ISO/IEC 7816-4, ICAO 9303 for the MRZ | `native_card.py`, `card_reader.py` |
| Token interface | PKCS#11 | `pkcs11_utils.py`, `signing.py` |
| CMS / CAdES | RFC 5652 | `cms_sign.py`, `cms_verify.py` |
| PAdES | ETSI EN 319 142-1 | `signing.py`, pyHanko |
| XAdES | ETSI EN 319 132-1 | `xml_sign.py`, `xml_verify.py` |
| Timestamps | RFC 3161 | `signing.py`, `verify_common.py` |
| Certificate validation | RFC 5280 path validation, local anchors | `national_ca.py`, `verify_common.py` |
| Secrets | No secret in `argv`, no echo, no logging, no persistence | `pin.py`, `signing.py` |
| File safety | Atomic replace, no symlink following, permission preservation | `signing.py` |
| Input validation | Size limits, safe XML parser, batch confinement | `xml_sign.py`, `pdf_verify.py`, `cms_verify.py` |
| Network | Destination allow rule, redirect and size limits, no ambient credentials | `outbound.py` |
| Supply chain | Pinned dependencies, OIDC publishing, protected environment | `pyproject.toml`, `uv.lock`, release workflow |

The project's test suite enforces these controls with regression tests, including the
timestamp-focused invariants in [security-invariants.md](security-invariants.md) and the
simulated-reader integration tests.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's private vulnerability reporting on
the upstream repository, as described in [SECURITY.md](https://github.com/carlosplanchon/firmauy/blob/main/SECURITY.md).
Reports in Spanish or English are welcome.

