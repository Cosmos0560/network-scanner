"""Ephemeral certificates for the lab and the tests (decision D2: nothing is committed).

Everything here is generated at runtime with `cryptography`. Keys live in memory; the only
time a key touches the disk is when a TLS server needs files to load, and then it goes into a
temporary directory that is deleted straight away (see `lab/services.py`). The builder can
produce the shapes the certificate reader has to tell apart: self-signed, issued by a CA,
"self-issued" with a signature that does not verify, and the reverse, plus expired and
wrong-name certificates, because validity and names are parameters.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


class KeyType(StrEnum):
    EC = "ec"
    RSA = "rsa"
    ED25519 = "ed25519"


def new_key(key_type: KeyType = KeyType.EC) -> PrivateKey:
    if key_type is KeyType.RSA:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type is KeyType.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(ec.SECP256R1())


@dataclass(frozen=True, slots=True)
class LabCertificate:
    certificate: x509.Certificate
    private_key: PrivateKey

    @property
    def der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    def write_pem_files(self, directory: Path) -> tuple[Path, Path]:
        """Write the certificate and the unencrypted key into `directory`; returns both paths.

        The key file is created with owner-only permissions where the platform has them.
        """
        certificate_path = directory / "lab-certificate.pem"
        key_path = directory / "lab-key.pem"
        certificate_path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))
        key_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key_pem)
        return certificate_path, key_path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def issue(
    *,
    common_name: str,
    not_before: datetime,
    not_after: datetime,
    dns_names: tuple[str, ...] = (),
    ip_addresses: tuple[str, ...] = (),
    issuer: LabCertificate | None = None,
    issuer_common_name: str | None = None,
    signing_key: PrivateKey | None = None,
    is_ca: bool = False,
    key_type: KeyType = KeyType.EC,
    rsa_padding: padding.PSS | padding.PKCS1v15 | None = None,
) -> LabCertificate:
    """Build a certificate with a fresh key.

    By default it is self-signed. `issuer` makes a CA sign it (the issuer name and the signing
    key come from that CA). `issuer_common_name` and `signing_key` override the issuer name and
    the key that signs, which is how tests build a certificate whose names say "self-issued"
    while the signature does not verify, or the reverse. `rsa_padding` selects PSS for RSA.
    """
    key = new_key(key_type)
    if signing_key is not None:
        signer = signing_key
    else:
        signer = issuer.private_key if issuer is not None else key
    if issuer_common_name is not None:
        issuer_name = _name(issuer_common_name)
    elif issuer is not None:
        issuer_name = issuer.certificate.subject
    else:
        issuer_name = _name(common_name)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    names: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    names.extend(x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses)
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)

    if isinstance(signer, ed25519.Ed25519PrivateKey):
        certificate = builder.sign(signer, None)
    elif isinstance(signer, rsa.RSAPrivateKey):
        certificate = builder.sign(signer, hashes.SHA256(), rsa_padding=rsa_padding)
    else:
        certificate = builder.sign(signer, hashes.SHA256())
    return LabCertificate(certificate, key)


def default_lab_certificate() -> LabCertificate:
    """A self-signed certificate for `localhost`, valid from yesterday until tomorrow."""
    now = datetime.now(UTC)
    return issue(
        common_name="network-scanner-lab",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=1),
        dns_names=("localhost",),
        ip_addresses=("127.0.0.1", "::1"),
    )
