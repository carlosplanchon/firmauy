# Bundled trust anchors: provenance

These are the **public** Uruguayan national PKI Certification Authority certificates, bundled
so that signature **verification** (`verify-pdf` / `verify-xml` / `verify-any`) can validate the
chain to the national root **offline, out of the box**. They are trust anchors only: public
certificates (signed public keys), not private keys, and not creative works. No signing key is
included.

They are loaded only after being re-checked against the pinned SHA-256 fingerprints in
`national_ca.py` (and the intermediate is checked to be signed by the root), so a tampered copy
is rejected regardless of how it got here.

| File | Certificate | SHA-256 (DER) | Valid until |
|------|-------------|---------------|-------------|
| `acrn.pem` | AC Raíz Nacional de Uruguay (AGESIC) | `5533a0401f612c688ebce5bf53f2ec14a734eb178bfae00e50e85dae6723078a` | 2031-10-29 |
| `mica.pem` | AC del Ministerio del Interior (issues the cédula) | `a29cad5c89aa49cff81f17f45c42fd44685510246d9ab5d031448e2fda2517be` | 2031-10-27 |

## Sources

- **Root (`acrn.pem`)**: published by AGESIC/UCE at `https://www.uce.gub.uy/acrn/acrn.cer`
  (still reachable at the time of writing).
- **Intermediate (`mica.pem`)**: originally published by the Ministerio del Interior at
  `https://ca.minterior.gub.uy/certificados/MICA.cer`. That server has been **decommissioned**
  (returns HTTP 501), and AGESIC's accredited-providers page still points at the dead URL, so the
  bundled copy was obtained from the public Certificate Transparency log
  (`https://crt.sh/?d=29172099`) and confirmed byte-identical to a copy that validates a real
  cédula chain. The two certificates are byte-for-byte identical to those fingerprints.

To refresh or override these at runtime, use `firmauy fetch-cas` (re-downloads, with a crt.sh
fallback), `firmauy fetch-cas --from-file <pem>`, or `verify-* --ca-file <pem>`.
