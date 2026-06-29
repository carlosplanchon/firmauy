# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Standards-based CAdES-BES detached signing (CMS / PKCS#7) for arbitrary files.

Completes the AdES triad next to PAdES (PDF) and XAdES (XML): sign *any* file with
the cédula, producing a detached ``.p7s`` (RFC 5652 CMS, CAdES-BES profile). The
signature is **detached**: the original file is left untouched and the signature
lives in the ``.p7s``. It carries RSA-SHA256 plus the ``signing-certificate-v2``
signed attribute (the CAdES marker, the CMS counterpart of the XAdES
SigningCertificate).

Unlike XAdES, pyHanko exposes the exact primitive (``Signer.sign_general_data``) and
a ``PKCS11Signer``, so this reuses the whole PDF plumbing (token, PIN, certificate
selection) with no manual cryptography.
"""

import asyncio
from typing import IO, Union

from pyhanko.sign.signers import Signer


def sign_cms_detached(
    input_data: Union[bytes, IO],
    *,
    signer: Signer,
    digest_algorithm: str = "sha256",
    timestamper=None,
) -> bytes:
    """Produce a detached CAdES signature over ``input_data``.

    ``input_data`` may be raw bytes or a binary file-like object (streamed, so large
    files are not loaded into memory). Returns the DER-encoded CMS ``ContentInfo``
    (the ``.p7s`` payload).

    Without ``timestamper`` the profile is CAdES-BES; passing a ``timestamper``
    (a pyHanko ``TimeStamper``, e.g. ``HTTPTimeStamper``) upgrades it to CAdES-T.
    """
    content_info = asyncio.run(
        signer.async_sign_general_data(
            input_data,
            digest_algorithm,
            detached=True,
            use_cades=True,
            timestamper=timestamper,
        )
    )
    return content_info.dump()
