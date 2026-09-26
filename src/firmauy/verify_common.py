# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Shared result types and helpers for signature verification (XML, PDF and CMS).

Indication model (mirrors the EU DSS semantics):
- VALID:         integrity holds and the chain is trusted.
- INDETERMINATE: integrity holds but trust could not be established / was not checked.
- INVALID:       the signature is broken or the document was modified.
"""

import hashlib
import logging
from contextlib import contextmanager

from asn1crypto import cms
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Check names for a signature timestamp, shared by the PDF and CMS verifiers. XAdES has its own
# pair carrying "XAdES-T", which is meaningful there and is left alone.
TS_PRESENT = "signature timestamp present (TSA not trust-validated)"
TS_TRUSTED = "signature timestamp (TSA chain validated)"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class TimestampInfo:
    """What is known about a signature's RFC 3161 timestamp, as data rather than as prose.

    The three-valued fields are the point. ``None`` means *not evaluated*, which is neither a
    pass nor a failure and is the usual case: without TSA trust anchors the token's chain is
    never checked, and a consumer that reads False there would be reporting a problem that was
    never looked for. pyHanko itself returns ``trusted=False`` in that situation, so the
    distinction has to be restored here, where it is known whether anchors were supplied.

    A timestamp says *when* a signature existed. It is separate from whether the signature is
    valid, and worth keeping separate: a document can carry a perfectly good signature and a
    broken timestamp, and saying so needs two verdicts, not one.
    """

    present: bool = False
    intact: Optional[bool] = None       # the token's own signature is unbroken
    valid: Optional[bool] = None        # ...and cryptographically correct
    trusted: Optional[bool] = None      # the TSA chain reached a trusted root
    gen_time: Optional[datetime] = None
    tsa_common_name: str = ""
    detail: str = ""                    # why, when something is not True


@dataclass
class VerifyResult:
    indication: str                 # VALID | INDETERMINATE | INVALID
    checks: list = field(default_factory=list)
    # Structured {common_name, serial_number, organization, country[, certificate_serial]};
    # uniform across the XML/PDF/CMS verifiers (see cert_utils.name_fields).
    signer: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    trusted: bool = False
    # None when the format carries no timestamp. A consumer should read this rather than parse
    # the check rows: the rows are display and their wording differs per format.
    timestamp: Optional[TimestampInfo] = None


# The unsigned CMS attribute an RFC 3161 signature timestamp travels in (id-aa-timeStampToken).
_TST_ATTR = "signature_time_stamp_token"

# The row every verifier uses for the signer's own chain, named once so the note below can find it.
CHAIN_CHECK = "certificate chain to trusted root"


def no_trust_context(moment):
    """The signer's validation context when no trust anchors were given (--no-trust, and the
    check after signing).

    An explicit empty list of roots, not None. pyhanko-certvalidator reads None as the operating
    system's trust store, a fallback it deprecated in 0.32 and will stop honouring, which would
    break these paths on a fresh install. And while it lasts, a signer whose chain reaches a root
    the system trusts comes back trusted from a verification that was told not to evaluate trust.
    """
    from pyhanko_certvalidator import ValidationContext

    return ValidationContext(trust_roots=[], allow_fetching=False, revocation_mode="soft-fail",
                             moment=moment)


def revocation_fetcher_backend(check_revocation: bool, allow_private_network: bool = False):
    """The fetcher backend for the signer's chain, or None when revocation is not checked.

    None keeps the offline default building exactly the context it always did. Otherwise every
    CRL, OCSP and AIA request goes through :mod:`firmauy.outbound`: requests, as before, so
    HTTP_PROXY and HTTPS_PROXY are honoured (pyhanko-certvalidator 0.32 moved its own default to
    an aiohttp session that ignores them), and under the outbound policy, because those URLs come
    from certificates, some of them not trusted yet. Internal destinations take
    ``allow_private_network`` (--allow-private-network). One backend per verified signature, so
    each has its own budget and its own record of what was refused.
    """
    if not check_revocation:
        return None
    from firmauy.revocation_fetchers import PolicyFetcherBackend

    return PolicyFetcherBackend(allow_private_network)


def refused_fetches_note(backend) -> str:
    """What the outbound policy refused while this chain was checked, as a clause for its row.

    Empty when nothing was refused, or when nothing was fetched at all (``backend`` None). Without
    it, the row only says the chain was not trusted, and certvalidator's own reason stops at
    "Failure to fetch CRL from URL ...": a refusal by firmauy would read like an outage, with
    nothing pointing at --allow-private-network.
    """
    refusals = getattr(backend, "refusals", None)
    if not refusals:
        return ""
    more = f" (and {len(refusals) - 1} more)" if len(refusals) > 1 else ""
    return f"revocation fetch refused by the outbound policy{more}: {refusals[0]}"


def note_refused_fetches(checks, backend) -> None:
    """Record on the chain row what the outbound policy refused, like :func:`note_trusted_time`."""
    note = refused_fetches_note(backend)
    if not note:
        return
    for check in checks:
        if check.name == CHAIN_CHECK:
            check.detail = f"{check.detail}; {note}" if check.detail else note


def note_trusted_time(checks, trusted_time) -> None:
    """Record on the chain row that it was judged at the timestamp's moment rather than at now.

    Worth saying out loud. A signature whose certificate expired years ago coming back VALID is
    surprising unless the row explains which day it was judged on, and somebody auditing the
    result should not have to infer that from the presence of a timestamp two rows down.

    Only when the chain passed. Under a failure the clause would read as the reason it failed,
    when the moment is what gave it its best chance.

    A known limitation this row makes visible rather than hides: with revocation checking on, the
    CRLs and OCSP responses are fetched *now* and then applied at that past moment, and a
    responder that will not answer for a date years back fails the chain. Carrying revocation data
    from signing time is the AdES ``-LT`` level, which firmauy does not produce. Combining
    ``--check-revocation`` with ``--tsa-ca`` is therefore the one combination that can be stricter
    than either alone.
    """
    if trusted_time is None:
        return
    suffix = f"evaluated at trusted genTime {trusted_time.isoformat()}"
    for check in checks:
        if check.name == CHAIN_CHECK and check.ok:
            check.detail = f"{check.detail}; {suffix}" if check.detail else suffix


class MalformedTimestamp(Exception):
    """A signature timestamp attribute is there, and it cannot be read.

    A distinct outcome from having no timestamp, and treating the two alike is what let a
    malformed ``TSTInfo`` crash the verifiers: reported as absent, the attribute was left in place
    for pyHanko to parse a second time, and the ValueError came back out of a public function.
    """


def _timestamp_attr(signer_info):
    """The signature-timestamp attribute, or None. Never raises: absent is a normal answer."""
    try:
        attrs = signer_info["unsigned_attrs"]
        if not attrs:
            return None
        for attr in attrs:
            if attr["type"].native == _TST_ATTR:
                return attr
    except Exception:
        return None
    return None


def extract_timestamp_token(signer_info) -> Optional[tuple]:
    """``(SignedData, genTime)``, or None when the signature carries no timestamp.

    Raises :class:`MalformedTimestamp` when there *is* a token and it cannot be read. Three
    outcomes, not two: absent, readable, and present-but-broken. The third is the one a file gets
    when somebody edits it, since the attribute is unsigned and rewriting it costs nothing.

    Read *before* the token is validated, which is the whole reason this exists. Two later
    decisions need the genTime and neither can wait for a verdict: the TSA's own certificate has
    to be judged at the moment it says it signed, and, once the token is trusted, so does the
    signer's. Building those validation contexts means knowing the moment first, and the moment
    is inside the token.

    Reading a claim is not believing it. Nothing here is trusted: this only decides *when* to
    evaluate, and whether the token holds up at that moment is decided afterwards, by the
    validation this time is used to set up. A forged genTime buys nothing on its own, because a
    token that does not chain to the supplied anchors fails regardless of which moment it is
    judged at.
    """
    attr = _timestamp_attr(signer_info)
    if attr is None:
        return None
    try:
        signed_data = attr["values"][0]["content"]
        tst_info = signed_data["encap_content_info"]["content"].parsed
        # ``.native`` on the whole TSTInfo, not just on gen_time, and that is the entire point.
        # asn1crypto parses lazily: reading one field leaves its siblings untouched, so a token
        # whose messageImprint algorithm is damaged hands back a perfectly good genTime here and
        # then raises later, inside pyHanko, out of a public function. Forcing the parse now moves
        # every structural failure to the one place that is prepared for it.
        tst_info.native
        # Structurally sound is not the same as usable. The messageImprint can name a hash nobody
        # implements, in which case the OID parses perfectly and the digest cannot be computed, so
        # validation raises later for a token this function already looked at and approved. Doing
        # the same lookup that will be needed anyway turns that into the answer it should be.
        hashlib.new(tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native)
        return signed_data, tst_info["gen_time"].native
    except Exception as exc:
        raise MalformedTimestamp(f"{type(exc).__name__}: {str(exc).splitlines()[0][:80]}") from exc


def drop_timestamp_token(signer_info) -> bool:
    """Remove the signature-timestamp attribute in memory. True when there was one.

    Sound because the attribute is *unsigned*: it is not covered by the signature, so taking it
    out cannot change what the signature says about the document. Used only for a token that has
    already been reported as unreadable, so that pyHanko can go on and give a verdict about the
    signature instead of raising on the same bytes we already failed to parse. Without this a
    broken token takes the whole result down with it, and the person is told nothing at all about
    a signature that may well be fine.
    """
    attrs = signer_info["unsigned_attrs"]
    if not attrs:
        return False
    keep = [a for a in attrs if a["type"].native != _TST_ATTR]
    if len(keep) == len(attrs):
        return False
    if keep:
        signer_info["unsigned_attrs"] = cms.CMSAttributes(keep)
    else:
        del signer_info["unsigned_attrs"]
    return True


def timestamp_of(signer_info, tsa_trust_roots=None, tsa_other_certs=None) -> tuple:
    """``(TimestampInfo, Check, trusted_time)`` for a CMS SignerInfo's signature timestamp.

    ``(None, None, None)`` when there is no timestamp. Shared by the PDF and CMS verifiers, which
    ask this question identically; XAdES finds its token in an XML element and names its checks
    differently, so it reaches :func:`evaluate_timestamp` by its own route.

    Judged before anything else, and that ordering is the point: which moment to judge the TSA's
    certificate at, and which moment to judge the signer's, both depend on the answer, and both
    are validation contexts that have to be built before pyHanko is called.
    """
    name = TS_TRUSTED if tsa_trust_roots else TS_PRESENT
    try:
        token = extract_timestamp_token(signer_info)
    except MalformedTimestamp as exc:
        # Out of the way, so the signature still gets a verdict. See drop_timestamp_token.
        drop_timestamp_token(signer_info)
        detail = f"could not parse timestamp: {exc}"
        return (TimestampInfo(present=True, intact=False, valid=False, detail=detail),
                Check(name, False, detail), None)
    if token is None:
        return None, None, None
    signed_data, gen_time = token
    return evaluate_timestamp(
        signed_data, gen_time, timestamp_imprint_source(signer_info),
        present_name=TS_PRESENT, trusted_name=TS_TRUSTED,
        tsa_trust_roots=tsa_trust_roots, tsa_other_certs=tsa_other_certs,
    )


def timestamp_imprint_source(signer_info) -> bytes:
    """The bytes an RFC 3161 *signature* timestamp is taken over: the signature itself.

    Spelled out rather than borrowed from ``pyhanko.sign.validation.generic_cms``, which has an
    equivalent helper but not as public API. It is one line, and a private import that moves
    upstream would take the timestamp row down with it.
    """
    return signer_info["signature"].native


def validate_timestamp_token(signed_data, imprint_over: bytes, gen_time,
                             tsa_trust_roots=None, tsa_other_certs=None) -> tuple:
    """Run pyHanko over an RFC 3161 token: ``(intact, valid, trusted, signing_cert, error)``.

    Three separate questions, kept separate. Collapsing them reports a sound token under the
    wrong anchor as broken, which sends a reader to inspect the file when the problem is in the
    anchors they passed. ``intact`` is the messageImprint binding, ``valid`` the token's own
    signature, ``trusted`` its chain, and only the third depends on anchors.

    ``trusted`` is None without anchors, because nothing was put to any anchor. The other two are
    answered either way: they are properties of the token, not of who vouches for it.

    ``imprint_over`` is whatever the messageImprint covers, which differs by format: the
    canonicalized ``<ds:SignatureValue>`` for XAdES, the raw signature bytes for PDF and CMS.
    Everything after that point is identical, which is why it lives here.
    """
    import asyncio

    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
    from pyhanko.sign.validation.status import TimestampSignatureStatus
    from pyhanko_certvalidator import ValidationContext

    from firmauy.cert_utils import to_asn1_certs

    def imprint(hash_algo: str) -> bytes:
        return hashlib.new(hash_algo, imprint_over).digest()

    try:
        vc = ValidationContext(
            # An explicit empty list, not None: None means the operating system's trust store, and
            # a TSA that happens to be in it would then be judged against anchors the caller never
            # supplied. Whatever it decides about trust is discarded below anyway.
            trust_roots=to_asn1_certs(tsa_trust_roots) if tsa_trust_roots else [],
            other_certs=to_asn1_certs(tsa_other_certs),
            allow_fetching=False,
            revocation_mode="soft-fail",
            moment=gen_time,   # validate the TSA certificate at the time it claims to have signed
        )
        with muted_path_building_warnings():
            kwargs = asyncio.run(validate_tst_signed_data(signed_data, vc, imprint))
        status = TimestampSignatureStatus(**kwargs)
    except Exception as exc:
        return False, False, None, None, f"TSA validation error: {str(exc)[:80]}"

    trusted = bool(status.trusted) if tsa_trust_roots else None
    return (bool(status.intact), bool(status.valid), trusted,
            getattr(status, "signing_cert", None), None)


def evaluate_timestamp(signed_data, gen_time, imprint_over: bytes, *, present_name: str,
                       trusted_name: str, tsa_trust_roots=None, tsa_other_certs=None) -> tuple:
    """``(TimestampInfo, Check, trusted_time)`` for a token that was found and parsed.

    One implementation for all three formats. The check *names* differ (XAdES says "XAdES-T" in
    its pair, and changing a released check's wording is not free), so they come in as arguments;
    everything else about judging a timestamp is the same question regardless of what the file
    around it looks like.

    ``trusted_time`` is the genTime, and only when the token fully validated. It is what a caller
    evaluates the *signing* certificate at, so it must not be handed back on anything less: an
    untrusted token's date is a claim by a stranger, and treating it as proof would let whoever
    could alter the file choose which day their certificate was checked on.
    """
    name = trusted_name if tsa_trust_roots else present_name
    intact, valid, trusted, cert, error = validate_timestamp_token(
        signed_data, imprint_over, gen_time, tsa_trust_roots, tsa_other_certs)

    info = TimestampInfo(
        present=True, intact=intact, valid=valid, trusted=trusted, gen_time=gen_time,
        # pyHanko hands back an asn1crypto certificate here, not a cryptography one, so
        # cert_utils.get_common_name (which takes the latter) does not apply.
        tsa_common_name=dict(cert.subject.native).get("common_name", "") if cert else "",
    )

    if error is not None:
        info.detail = error
        return info, Check(name, False, error), None
    if intact and valid and trusted:
        info.detail = f"genTime {gen_time.isoformat()} (trusted)"
        return info, Check(name, True, info.detail), gen_time
    if intact and valid and trusted is None:
        info.detail = f"genTime {gen_time.isoformat()} (asserted by the TSA, not verified)"
        return info, Check(name, True, info.detail), None

    # One reason, the most fundamental one that applies. A token that does not bind to this
    # signature is not this signature's timestamp at all, so that is worth saying before anything
    # about who issued it.
    if not intact:
        info.detail = "timestamp does not match the signature value"
    elif not valid:
        info.detail = "timestamp token signature is invalid"
    else:
        info.detail = "TSA chain does not reach a trusted root"
    return info, Check(name, False, info.detail), None


# pyHanko logs a full traceback at WARNING when it cannot build a trust path during CMS or
# PDF validation (both go through ``pyhanko.sign.validation.generic_cms``). That is an
# *expected* outcome: no trust anchors (--no-trust / no cached CAs) or a chain that does not
# reach a trusted root, which the verifiers already surface cleanly as INDETERMINATE via the
# per-check breakdown. Keep that traceback out of the user's terminal.
_PYHANKO_PATH_LOGGER = "pyhanko.sign.validation.generic_cms"


@contextmanager
def muted_path_building_warnings():
    """Temporarily raise the pyHanko path-building logger to ERROR, restoring it after."""
    logger = logging.getLogger(_PYHANKO_PATH_LOGGER)
    prev_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(prev_level)
