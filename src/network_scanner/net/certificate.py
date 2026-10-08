"""Describe a peer certificate without trusting it.

The input is the raw DER bytes the server sent, which is hostile input. Parsing is done by
the `cryptography` library (decision D1), after a size check, and every failure becomes data
(`TlsInfo.parse_error`, one of a few fixed codes) instead of an exception, so a malformed or
oversized certificate can never stop a scan. All text taken from the certificate is passed
through the sanitiser and capped.

Nothing here validates the certificate. Facts are reported, not judged:

- `self_issued` is whether issuer and subject name are equal;
- `self_signature_valid` is whether the signature verifies under the certificate's own public
  key. The two are separate facts (decision D6): a certificate can claim to be self-issued
  with a signature that does not verify, and a certificate with different names can be signed
  by its own key. Neither says anything about whether anyone should trust it;
- `expired` is whether the injected `now` is after notAfter (a not-yet-valid certificate is
  not reported as expired; `not_before` is there to see);
- `hostname_match` is whether the requested name matches a subjectAltName entry (RFC 9525
  rules: the subject common name is not consulted, a wildcard is one whole left-most label).
  It is None when no name was requested.

No chain is built and no trust store is consulted.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from network_scanner.core.limits import MAX_CERT_DER_BYTES, MAX_CERT_FIELD_CHARS, MAX_SAN_ENTRIES
from network_scanner.core.model import TlsInfo
from network_scanner.core.sanitize import sanitize_text

NO_CERTIFICATE = "no_certificate"
CERTIFICATE_TOO_LARGE = "certificate_too_large"
MALFORMED_CERTIFICATE = "malformed_certificate"


def _clean(text: str) -> str:
    return sanitize_text(text, max_chars=MAX_CERT_FIELD_CHARS).text


def _dns_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if not pattern or not host:
        return False
    if "*" not in pattern:
        return pattern == host
    labels = pattern.split(".")
    # A wildcard is the whole left-most label, with at least two labels after it (no "*.com").
    if labels[0] != "*" or "*" in ".".join(labels[1:]) or len(labels) < 3:
        return False
    host_labels = host.split(".")
    return (
        len(host_labels) == len(labels) and host_labels[0] != "" and host_labels[1:] == labels[1:]
    )


def hostname_matches(
    server_name: str,
    dns_names: list[str],
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> bool:
    """Whether `server_name` is covered by the subjectAltName entries given."""
    try:
        wanted = ipaddress.ip_address(server_name)
    except ValueError:
        return any(_dns_matches(name, server_name) for name in dns_names)
    return wanted in ip_addresses


def signature_verifies_under_own_key(certificate: x509.Certificate) -> bool | None:
    """Whether the signature verifies under the certificate's own public key.

    A signature made with another kind of key (an RSA certificate signed by an EC authority,
    say) cannot verify under this one, which is a plain False. None means the check could not
    be made at all: a public key type or signature algorithm this library cannot verify.
    """
    key = certificate.public_key()
    signature, signed = certificate.signature, certificate.tbs_certificate_bytes
    try:
        if isinstance(key, rsa.RSAPublicKey):
            scheme = certificate.signature_algorithm_parameters
            hash_algorithm = certificate.signature_hash_algorithm
            if not isinstance(scheme, padding.PKCS1v15 | padding.PSS) or hash_algorithm is None:
                return False
            key.verify(signature, signed, scheme, hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            scheme = certificate.signature_algorithm_parameters
            if not isinstance(scheme, ec.ECDSA):
                return False
            key.verify(signature, signed, scheme)
        elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            key.verify(signature, signed)
        else:
            return None
    except InvalidSignature:
        return False
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return None
    return True


def _failed(version: str | None, cipher: str | None, sha256: str | None, code: str) -> TlsInfo:
    return TlsInfo(
        version=version,
        cipher=cipher,
        subject=None,
        issuer=None,
        not_before=None,
        not_after=None,
        san=(),
        san_truncated=False,
        sha256=sha256,
        self_issued=None,
        self_signature_valid=None,
        expired=None,
        hostname_match=None,
        parse_error=code,
    )


def describe_certificate(
    der: bytes | None,
    *,
    version: str | None,
    cipher: str | None,
    server_name: str | None,
    now: datetime,
) -> TlsInfo:
    """Facts about the certificate in `der`; never raises for bad certificate data."""
    version = None if version is None else _clean(version)
    cipher = None if cipher is None else _clean(cipher)
    if der is None:
        return _failed(version, cipher, None, NO_CERTIFICATE)
    sha256 = hashlib.sha256(der).hexdigest()
    if len(der) > MAX_CERT_DER_BYTES:
        return _failed(version, cipher, sha256, CERTIFICATE_TOO_LARGE)
    try:
        return _describe(der, version, cipher, sha256, server_name, now)
    except Exception:  # untrusted input and a parser written in another language: see module doc
        return _failed(version, cipher, sha256, MALFORMED_CERTIFICATE)


def _describe(
    der: bytes,
    version: str | None,
    cipher: str | None,
    sha256: str,
    server_name: str | None,
    now: datetime,
) -> TlsInfo:
    certificate = x509.load_der_x509_certificate(der)
    subject = _clean(certificate.subject.rfc4514_string())
    issuer = _clean(certificate.issuer.rfc4514_string())
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    dns_names: list[str] = []
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        dns_names = list(extension.value.get_values_for_type(x509.DNSName))
        ip_addresses = [
            address
            for address in extension.value.get_values_for_type(x509.IPAddress)
            if isinstance(address, ipaddress.IPv4Address | ipaddress.IPv6Address)
        ]
    shown = [f"DNS:{name}" for name in dns_names] + [f"IP:{address}" for address in ip_addresses]

    return TlsInfo(
        version=version,
        cipher=cipher,
        subject=subject,
        issuer=issuer,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        san=tuple(_clean(entry) for entry in shown[:MAX_SAN_ENTRIES]),
        san_truncated=len(shown) > MAX_SAN_ENTRIES,
        sha256=sha256,
        self_issued=certificate.issuer == certificate.subject,
        self_signature_valid=signature_verifies_under_own_key(certificate),
        expired=now > not_after,
        hostname_match=(
            None if server_name is None else hostname_matches(server_name, dns_names, ip_addresses)
        ),
        parse_error=None,
    )
