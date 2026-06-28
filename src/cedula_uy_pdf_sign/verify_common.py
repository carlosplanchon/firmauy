# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Shared result types for signature verification (XML and PDF).

Indication model (mirrors the EU DSS semantics):
- VALID:         integrity holds and the chain is trusted.
- INDETERMINATE: integrity holds but trust could not be established / was not checked.
- INVALID:       the signature is broken or the document was modified.
"""

from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyResult:
    indication: str                 # VALID | INDETERMINATE | INVALID
    checks: list = field(default_factory=list)
    signer: str = ""
    issuer: str = ""
    trusted: bool = False
