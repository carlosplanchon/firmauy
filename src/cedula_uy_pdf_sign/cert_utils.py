# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.x509.oid import NameOID


def name_fields(name) -> dict:
    """Extract a uniform ``{common_name, serial_number, organization, country}`` dict from an
    X.509 Name, accepting either a ``cryptography`` or an ``asn1crypto`` Name. Missing
    attributes are ``None``. Used to build a consistent, structured signer/issuer across the
    XML (cryptography) and PDF/CMS (asn1crypto) verifiers."""
    if isinstance(name, asn1x509.Name):
        native = name.native or {}
        return {
            "common_name": native.get("common_name"),
            "serial_number": native.get("serial_number"),
            "organization": native.get("organization_name"),
            "country": native.get("country_name"),
        }

    def _first(oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    return {
        "common_name": _first(NameOID.COMMON_NAME),
        "serial_number": _first(NameOID.SERIAL_NUMBER),
        "organization": _first(NameOID.ORGANIZATION_NAME),
        "country": _first(NameOID.COUNTRY_NAME),
    }


def get_common_name(name: x509.Name) -> str:
    """Return the CN from an x509.Name, falling back to the RFC 4514 string."""
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return name.rfc4514_string()


def normalize_issuer_name(name: str) -> str:
    """Normalize whitespace and apply known display aliases."""
    normalized = " ".join(name.split()).strip()
    if normalized.upper() == "AUTORIDAD CERTIFICADORA DEL MINISTERIO DEL INTERIOR":
        return "Autoridad Certificadora del Ministerio del Interior"
    return normalized


def cert_not_after(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_after_utc.strftime("%Y-%m-%d")
    except AttributeError:
        return cert.not_valid_after.strftime("%Y-%m-%d")  # type: ignore[attr-defined]


def cert_not_before(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_before_utc.strftime("%Y-%m-%d")
    except AttributeError:
        return cert.not_valid_before.strftime("%Y-%m-%d")  # type: ignore[attr-defined]
