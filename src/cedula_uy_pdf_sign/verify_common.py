# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Shared result types and helpers for signature verification (XML, PDF and CMS).

Indication model (mirrors the EU DSS semantics):
- VALID:         integrity holds and the chain is trusted.
- INDETERMINATE: integrity holds but trust could not be established / was not checked.
- INVALID:       the signature is broken or the document was modified.
"""

import logging
from contextlib import contextmanager
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
