# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""CAdES / detached CMS (.p7s) verification (the verify side of ``cms_sign``).

Tiered like the XML/PDF verifiers:

- **Level 1** (offline, always): signature integrity, the signed bytes hash to the
  embedded ``messageDigest`` and the signature is cryptographically valid.
- **Level 2** (offline, default): certificate chain to a trusted root (RFC 5280).
- **Level 3** (``check_revocation=True``): CRL/OCSP. Needs network.

A detached CMS signature has no PDF-style *coverage* notion: it signs exactly the
bytes it is verified against, so integrity already implies full coverage.
"""

import asyncio
from datetime import datetime, timezone
from typing import IO, Optional, Union

from asn1crypto import cms as asn1cms
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext

from firmauy.cert_utils import name_fields, to_asn1_certs
from firmauy.verify_common import (
    CHAIN_CHECK,
    Check,
    VerifyResult,
    muted_path_building_warnings,
    note_refused_fetches,
    note_trusted_time,
    revocation_fetcher_backend,
    timestamp_of,
)

MAX_CMS_BYTES = 8 * 1024 * 1024


def _load_signed_data(p7s_bytes: bytes) -> asn1cms.SignedData:
    """Parse a DER-encoded ``.p7s`` into its CMS SignedData. Raises ValueError if it
    is not a CMS SignedData structure."""
    if len(p7s_bytes) > MAX_CMS_BYTES:
        raise ValueError(
            f"CMS signature exceeds the {MAX_CMS_BYTES} byte limit; refusing to parse it"
        )
    try:
        # Deliberately not strict=True: strict rejects trailing bytes after the DER structure,
        # and the parsers behind mainstream validators tolerate them (OpenSSL's d2i stops at the
        # end of the structure, BouncyCastle likewise). Refusing here would make this verifier
        # stricter than the official one over bytes no signature covers, the hybrid-xref lesson.
        ci = asn1cms.ContentInfo.load(p7s_bytes)
        content_type = ci["content_type"].native
    except Exception as exc:
        raise ValueError(f"not a valid CMS/.p7s structure: {exc}") from exc
    if content_type != "signed_data":
        raise ValueError(f"not a CMS SignedData (.p7s): content type is '{content_type}'")
    return ci["content"]



def _map_status(status, trust_evaluated: bool, info=None, ts_check=None) -> VerifyResult:
    intact = bool(getattr(status, "intact", False))
    valid = bool(getattr(status, "valid", False))
    trusted = bool(getattr(status, "trusted", False))

    checks = [
        Check("signature intact (signed bytes unmodified)", intact),
        Check("signature cryptographically valid", valid),
    ]
    if trust_evaluated:
        checks.append(Check(CHAIN_CHECK, trusted, "" if trusted else "not trusted"))

    cert = getattr(status, "signing_cert", None)
    if cert is not None:
        signer = {**name_fields(cert.subject), "certificate_serial": format(cert.serial_number, "X")}
        issuer = name_fields(cert.issuer)
    else:
        signer, issuer = {}, {}

    if not (intact and valid):
        indication = "INVALID"
    elif ts_check is not None and not ts_check.ok:
        # As in the PDF and XAdES paths: an unsigned attribute cannot make the signature INVALID,
        # but a broken one holds the verdict at INDETERMINATE rather than letting VALID stand
        # over a row that says the token does not check out.
        indication = "INDETERMINATE"
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    if ts_check is not None:
        checks.append(ts_check)

    return VerifyResult(indication, checks, signer, issuer, trusted, info)



def _tsa_context(tsa_trust_roots, tsa_other_certs, at):
    """A validation context for the timestamp alone, or None when no anchors were given.

    Deliberately separate from the signer's. ``trust_roots`` decides who is accepted as having
    *signed* the document, so folding a TSA's root into it to make a timestamp validate would
    quietly widen that, which is a security change and not a convenience. pyHanko takes the two
    contexts as separate arguments for this reason.

    ``at`` is the token's own genTime, supplied by the caller, and not the verification time. A
    TSA responder certificate is short-lived by design and the documents it stamps are not, so
    judging it now means every timestamp turns untrusted the day that certificate expires, which
    is the one thing a timestamp exists to prevent. This is what XAdES already did; PAdES and
    CAdES judged at ``at_time`` until 1.12.1, so the same token flipped from trusted to untrusted
    with nothing about the file having changed.

    Optimistic without an archive timestamp, and knowingly so: a genTime is self-asserted, so
    strictly this needs proof the token existed before the certificate expired, which only a
    later timestamp can give (the AdES -LTA level, out of scope here). The exposure is a TSA key
    compromised after expiry, which is a smaller problem than every -T signature decaying on a
    schedule.
    """
    if not tsa_trust_roots:
        return None
    return ValidationContext(
        trust_roots=to_asn1_certs(tsa_trust_roots),
        other_certs=to_asn1_certs(tsa_other_certs),
        allow_fetching=False,
        revocation_mode="soft-fail",
        moment=at,
    )


def verify_cms(
    input_data: Union[bytes, IO],
    p7s_bytes: bytes,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
    allow_private_network: bool = False,
) -> VerifyResult:
    """Verify a detached CAdES/.p7s signature (``p7s_bytes``) over ``input_data``.

    With ``trust_roots`` it also validates the certificate chain (level 2); with
    ``check_revocation=True`` it also checks CRL/OCSP (level 3, needs network), fetched under the
    outbound policy (:mod:`firmauy.outbound`), which ``allow_private_network`` relaxes for
    internal mirrors. Otherwise only integrity is checked (level 1).

    ``tsa_trust_roots`` validates an RFC 3161 signature timestamp's own chain. Without it the
    timestamp is reported as present and unvalidated rather than as trusted or as broken. With it,
    a token that fully validates also fixes *when* the signing certificate is evaluated: at the
    trusted genTime rather than now, so a signature does not stop verifying the day the signer's
    certificate expires. That is the whole purpose of a timestamp, and until 1.13.0 only the XAdES
    verifier honoured it."""
    signed_data = _load_signed_data(p7s_bytes)
    at = at_time or datetime.now(timezone.utc)

    # First, because both moments below depend on the answer. See _timestamp_of.
    signer_infos = signed_data["signer_infos"]
    info, ts_check, trusted_time = (
        timestamp_of(signer_infos[0], tsa_trust_roots, tsa_other_certs)
        if len(signer_infos) else (None, None, None))

    vc = backend = None
    if trust_roots:
        backend = revocation_fetcher_backend(check_revocation, allow_private_network)
        vc = ValidationContext(
            trust_roots=to_asn1_certs(trust_roots),
            other_certs=to_asn1_certs(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            fetcher_backend=backend,
            # Only a *trusted* token moves the moment. An untrusted genTime is a claim by a
            # stranger, and letting it choose the day the signing certificate is checked on would
            # hand that choice to whoever could alter the file.
            moment=trusted_time or at,
        )

    ts_vc = _tsa_context(tsa_trust_roots, tsa_other_certs,
                         (info.gen_time if info else None) or at)
    with muted_path_building_warnings():
        status = asyncio.run(
            async_validate_detached_cms(input_data, signed_data, signer_validation_context=vc,
                                        ts_validation_context=ts_vc)
        )
    result = _map_status(status, bool(trust_roots), info, ts_check)
    note_trusted_time(result.checks, trusted_time)
    note_refused_fetches(result.checks, backend)
    return result
