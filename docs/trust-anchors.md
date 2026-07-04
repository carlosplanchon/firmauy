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
checked (2026-07-03) both returned `HTTP 200` (the cédula CRL is a ~13 MB file), so the chain's
revocation data was reachable. Revocation is `hard-fail`, so every CRL in the chain must be reachable
at check time or the chain fails, and this has not been re-confirmed end-to-end against a live cédula
signature. The default (no `--check-revocation`) stays fully offline.

## Validity over time

A basic (BES) signature carries no trusted timestamp, so certificate validity and revocation are
evaluated **at verification time**, not at signing time. A timestamp (PAdES-T / XAdES-T / CAdES-T,
added with `--tsa-url`) provides independent trusted-time evidence of when the signature existed.

On the verification side, that evidence is only as good as the timestamp's own validation. For PDF
(PAdES-T) and CMS (CAdES-T), pyHanko checks the embedded timestamp against the active trust
anchors, so it counts as trusted time only when the TSA's CA is among them (e.g. supplied via
`--ca-file`). For XML (XAdES-T), `firmauy verify-xml` confirms by default only that the timestamp
**binds to the signature**; it does **not** validate the TSA's certificate, so the reported
`genTime` is what the (unverified) TSA asserts. Pass **`--tsa-ca <tsa-bundle.pem>`** to validate the
RFC 3161 token against the timestamping authority's certificate: on success the `genTime` becomes
trusted and the signing certificate is then evaluated **at that time** instead of now (long-term
validation), so a signature stays VALID even after the signer's certificate later expires.

There is no national list of trusted timestamping authorities to bundle (unlike the national CA),
so `--tsa-ca` is bring-your-own: supply the CA of whichever TSA you used. Embedding revocation data
at signing time (the AdES `-LT` / `-LTA` levels, for full archival validation) is out of scope: it is
not implemented, independent of whether the CRL endpoints are reachable.

The bundled national CA certificates expire (2031) and can be rotated by the issuer; re-run
`firmauy fetch-cas` to refresh from the network, or use `--ca-file`.
