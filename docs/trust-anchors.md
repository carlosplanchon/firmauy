# Trust anchors and certificate pinning

How `firmauy` establishes trust when verifying cédula signatures: the national CA certificates it
uses, how they are pinned, how to refresh them, and the current state of revocation.

For everyday use you do not need any of this: the certificates are bundled and verification works
offline out of the box. This document is the deep dive.

## Bundled certificates, verified against pinned fingerprints

The package **bundles** the two national CA certificates as built-in trust anchors (public
certificates, see [`data/PROVENANCE.md`](https://github.com/carlosplanchon/cedula-uy-pdf-sign/blob/main/src/cedula_uy_pdf_sign/data/PROVENANCE.md)).
Verification uses them automatically, so it works offline with no setup; `firmauy fetch-cas` can
refresh them from the sources below into a per-user cache (which then takes precedence over the
bundled copies).

Every certificate (bundled, cached, downloaded, or supplied via `--ca-file` / `--from-file`) is
verified against a pinned SHA-256 fingerprint, and the intermediate is additionally checked to be
signed by the root, so the origin of the bytes never matters.

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
curl -s -A "firmauy (+https://pypi.org/project/cedula-uy-pdf-sign)" "https://crt.sh/?d=29172099" \
  | openssl x509 -noout -fingerprint -sha256
# SHA256 Fingerprint=A2:9C:AD:5C:...:BE
```

## Revocation (CRL/OCSP)

Revocation checking is **off by default** (offline). With `--check-revocation`, verification
fetches revocation data and fails the chain (`hard-fail`) if the certificate is revoked or that
data cannot be obtained.

For **cédula** signatures, `--check-revocation` currently **cannot succeed**: the leaf
certificate's CRL distribution point is on the Ministerio del Interior server
(`ca.minterior.gub.uy`), which has been decommissioned and returns `HTTP 501`. Since revocation
is `hard-fail`, unreachable revocation data fails the chain. Use the default
(no `--check-revocation`) until the CRL endpoint is restored.

## Validity over time

A basic (BES) signature carries no trusted timestamp, so certificate validity and revocation are
evaluated **at verification time**, not at signing time. A timestamp (PAdES-T / XAdES-T / CAdES-T,
added with `--tsa-url`) provides independent trusted-time evidence of when the signature existed.

The bundled national CA certificates expire (2031) and can be rotated by the issuer; re-run
`firmauy fetch-cas` to refresh from the network, or use `--ca-file`.
