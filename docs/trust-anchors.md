# Trust anchors and certificate pinning

How `firmauy` establishes trust when verifying cédula signatures: the national CA certificates it
uses, how they are pinned, how to refresh them, and the current state of revocation.

For everyday use you do not need any of this: the certificates are bundled and verification works
offline out of the box. This document is the deep dive.

## Bundled certificates, verified against pinned fingerprints

The package **bundles** the two national CA certificates as built-in trust anchors (public
certificates, see [`data/PROVENANCE.md`](https://github.com/carlosplanchon/firmauy/blob/main/src/firmauy/data/PROVENANCE.md)).
Verification uses them automatically, so it works offline with no setup; `firmauy fetch-cas` can
refresh them from the sources below into a per-user cache (which then takes precedence over the
bundled copies).

Every certificate on the *national-CA path* (bundled, cached, downloaded, or seeded via
`--from-file`) is verified against a pinned SHA-256 fingerprint, and the intermediate is
additionally checked to be signed by the root, so the origin of those bytes never matters.
(`--ca-file` is different: it lets you supply your *own* trust anchors for verification, so it is
intentionally **not** pinned, the whole point being to trust a set you chose.)

| Certificate | Source(s), tried in order |
|---|---|
| AC Raíz Nacional de Uruguay (AGESIC) | `https://www.uce.gub.uy/acrn/acrn.cer` |
| AC Ministerio del Interior (intermediate) | `https://ca.minterior.gub.uy/certificados/MICA.cer` (official), then `https://crt.sh/?d=29172099` (fallback) |

> **Note on the intermediate source.** `fetch-cas` tries the official Ministerio del Interior
> repository first, then falls back to the **byte-identical** copy in the public Certificate
> Transparency log (crt.sh). Whatever the source, the bytes are accepted only if they match the
> pinned fingerprint below *and* are signed by the pinned root, so the origin never matters and the
> fallback needs no trust of its own. When last checked (2026-07-03) the official `MICA.cer` URL
> returned `HTTP 200` and crt.sh was timing out, which is exactly the case the fingerprint pin plus
> fallback are meant to cover.

## `fetch-cas` (optional)

`fetch-cas` is **optional**: verification already uses the bundled certificates; it only
refreshes a per-user cache. If you do run it and crt.sh is flaky, you can seed the intermediate
from a local copy with `--from-file` instead of downloading. The fingerprint pin makes the
file's origin irrelevant; a copy that doesn't match a pin is ignored and downloaded instead:

```bash
# Seed the intermediate from a local file; the root still downloads (it is reliable)
firmauy fetch-cas --from-file mica.pem

# Fully offline: supply both (a bundle, or repeat --from-file)
firmauy fetch-cas --from-file acrn.pem --from-file mica.pem
```

Any certificate matching a pinned fingerprint is taken from the supplied file(s) instead of
being downloaded. (The cédula middleware does **not** install these certificates, and the
package already bundles them, so you rarely need this.)

## Pinned fingerprints

SHA-256 of each certificate (DER):

```text
root (ACRN):         5533a0401f612c688ebce5bf53f2ec14a734eb178bfae00e50e85dae6723078a
intermediate (MICA): a29cad5c89aa49cff81f17f45c42fd44685510246d9ab5d031448e2fda2517be
```

You can audit them yourself:

```bash
# Root, from the official source:
curl -s https://www.uce.gub.uy/acrn/acrn.cer | openssl x509 -noout -fingerprint -sha256
# SHA256 Fingerprint=55:33:A0:40:...:8A  (same bytes, openssl prints them upper-case with colons)

# Intermediate, from the Certificate Transparency log:
curl -s -A "firmauy (+https://pypi.org/project/firmauy)" "https://crt.sh/?d=29172099" \
  | openssl x509 -noout -fingerprint -sha256
# SHA256 Fingerprint=A2:9C:AD:5C:...:BE
```

## Revocation (CRL/OCSP)

Revocation checking is **off by default** (offline). With `--check-revocation`, verification
fetches revocation data and fails the chain (`hard-fail`) if the certificate is revoked or that
data cannot be obtained.

For **cédula** signatures this needs the Ministerio del Interior CRL endpoint
(`ca.minterior.gub.uy/crls/`) and the national root's CRL (`acrn.crl` on AGESIC/UCE). When last
checked (2026-09-26) both returned `HTTP 200`, so the chain's revocation data was reachable.
Revocation is `hard-fail`, so every CRL in the chain must be reachable at check time or the chain
fails, and this has not been re-confirmed end-to-end against a live cédula signature. The default
(no `--check-revocation`) stays fully offline.

The fetches go through the outbound policy described in
[docs/usage.md](usage.md#common-verification-options-and-output): public addresses only, a few
vetted redirects, and a size and time limit on each request. The limits come from what these
endpoints served on 2026-09-26:

| CRL | Size | Over `http://` |
|---|---|---|
| `ca.minterior.gub.uy/crls/crl.crl` (cédulas) | 13,208,654 bytes (12.6 MiB), reissued every 24 hours | 302 to `https://` |
| `ca.minterior.gub.uy/crls/crlmicaa1.crl` | 952 bytes | 200 |
| `ca.minterior.gub.uy/crls/crlmicac1.crl` | 1,926 bytes | 200 |
| `acrn.crl` (national root, AGESIC and UCE) | 991 bytes | 200 |

A CRL may take up to 64 MiB, about five times the cédula CRL, which grows as certificates are
revoked, and up to 5 minutes, enough for 12.6 MiB at about 350 kbit/s. The redirect from `http://`
to `https://` is why revocation fetches follow redirects at all.

## Validity over time

A basic (BES) signature carries no trusted timestamp, so certificate validity and revocation are
evaluated **at verification time**, not at signing time. A timestamp (PAdES-T / XAdES-T / CAdES-T,
added with `--tsa-url`) provides independent trusted-time evidence of when the signature existed.

On the verification side, that evidence is only as good as the timestamp's own validation, and
this works the same way in all three formats. By default firmauy confirms that the token is
intact, that its own signature is valid and that it **binds to the signature** it travels with,
but it does **not** validate the TSA's certificate, so the reported `genTime` is only what an
unverified TSA asserts. Pass **`--tsa-ca <tsa-bundle.pem>`** to validate the RFC 3161 token
against the timestamping authority's certificate. On success the `genTime` becomes trusted, and
the signing certificate is then evaluated **at that time** instead of now, in every format, so a
signature stays VALID even after the signer's certificate later expires. That is validation at
the sealed time, and not the AdES `-LT` / `-LTA` levels: no historical revocation evidence is
embedded at signing or consulted at verification.

`--tsa-ca` is kept separate from `--ca-file` on purpose, and pointing the latter at a timestamping
authority is not a substitute: `--ca-file` decides who is accepted as having **signed the
document**, so widening it to get a stamp validated widens who may sign. This page used to
recommend exactly that for PDF and CMS. It was wrong, and until 1.12.0 `--tsa-ca` was silently
ignored on those two formats, which is why the advice existed.

The TSA's certificate is evaluated at the token's `genTime`, not at verification time. A responder
certificate is short-lived and the documents it stamps are not, so judging it now would make every
timestamp turn untrusted the day that certificate expires, which is the one thing a timestamp
exists to prevent. That is optimistic without an archive timestamp (the AdES `-LTA` level, not
implemented): strictly, a self-asserted `genTime` needs independent proof the token existed before
the certificate expired.

The same applies one level up. Once the token itself is trusted, its `genTime` also decides when
the **signer's** certificate is evaluated, so a signature does not stop verifying the day the
cédula behind it expires. Only a trusted token does this: an unvalidated `genTime` is a claim by a
stranger, and letting it pick the day would hand that choice to whoever could alter the file. The
chain row records which day it used.

⚠️ Revocation checking and `--tsa-ca` together can be stricter than either alone. Revocation data
is fetched now and applied at the past moment, and a responder that will not answer for a date
years back fails the chain. Embedding revocation data at signing time is the `-LT` level, which is
out of scope here.

There is no national list of trusted timestamping authorities to bundle (unlike the national CA),
so `--tsa-ca` is bring-your-own: supply the CA of whichever TSA you used. Embedding revocation data
at signing time (the AdES `-LT` / `-LTA` levels, for full archival validation) is out of scope: it is
not implemented, independent of whether the CRL endpoints are reachable.

The bundled national CA certificates expire (2031) and can be rotated by the issuer before then.

**A rotation needs a new firmauy release, or `--ca-file`.** `fetch-cas` does not help: it accepts
bytes only when they match a fingerprint pinned in the source (`ACRN_SHA256` and `MICA_SHA256` in
`national_ca.py`), so a genuinely new certificate is rejected by the very check that makes the
download safe. That is the pin working as designed, and it is the trade: nobody can slip a
different root past it, including the issuer, until a human updates the pin and ships it. Until
that release exists, `--ca-file` is the way to verify against the new anchors, which is also the
tested path for anyone who wants to supply their own.
