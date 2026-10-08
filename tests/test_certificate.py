"""Certificate facts, against certificates generated at runtime (decision D2).

Nothing here is read from a file: each test builds the certificate it needs in memory with
`network_scanner.lab.certs`, so there is no key or certificate in the repository to go stale
or to be flagged by a secret scanner. All dates are fixed and the "current time" is passed in,
so the tests cannot rot as the calendar moves.
"""

from __future__ import annotations

import hashlib
import ipaddress
import random
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from network_scanner.core.limits import (
    MAX_CERT_DER_BYTES,
    MAX_CERT_FIELD_CHARS,
    MAX_SAN_ENTRIES,
)
from network_scanner.core.model import TlsInfo
from network_scanner.lab.certs import KeyType, LabCertificate, issue, new_key
from network_scanner.net.certificate import (
    CERTIFICATE_TOO_LARGE,
    MALFORMED_CERTIFICATE,
    NO_CERTIFICATE,
    describe_certificate,
    hostname_matches,
    signature_verifies_under_own_key,
)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 1, 1, tzinfo=UTC)
UNTIL = datetime(2027, 1, 1, tzinfo=UTC)


def describe(
    certificate: LabCertificate | bytes | None,
    *,
    server_name: str | None = None,
    now: datetime = NOW,
) -> TlsInfo:
    der = certificate.der if isinstance(certificate, LabCertificate) else certificate
    return describe_certificate(
        der, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", server_name=server_name, now=now
    )


def lab_certificate(**overrides: object) -> LabCertificate:
    settings: dict[str, object] = {
        "common_name": "lab.test",
        "not_before": FROM,
        "not_after": UNTIL,
        "dns_names": ("lab.test",),
        "ip_addresses": ("127.0.0.1",),
    }
    settings.update(overrides)
    return issue(**settings)  # type: ignore[arg-type]


# -- exact fields of a valid certificate -----------------------------------------------------


@pytest.mark.parametrize("key_type", list(KeyType))
def test_the_fields_of_a_valid_self_signed_certificate_are_exact(key_type: KeyType) -> None:
    certificate = lab_certificate(key_type=key_type)
    info = describe(certificate, server_name="lab.test")
    assert info == TlsInfo(
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        subject="CN=lab.test",
        issuer="CN=lab.test",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        san=("DNS:lab.test", "IP:127.0.0.1"),
        san_truncated=False,
        sha256=hashlib.sha256(certificate.der).hexdigest(),
        self_issued=True,
        self_signature_valid=True,
        expired=False,
        hostname_match=True,
        parse_error=None,
    )


def test_ipv6_subject_alternative_names_are_listed() -> None:
    info = describe(lab_certificate(ip_addresses=("::1", "2001:db8::1")))
    assert info.san == ("DNS:lab.test", "IP:::1", "IP:2001:db8::1")


def test_a_certificate_without_subject_alternative_names_has_none() -> None:
    info = describe(lab_certificate(dns_names=(), ip_addresses=()), server_name="lab.test")
    assert info.san == ()
    assert info.hostname_match is False  # the common name alone is not consulted (RFC 9525)


# -- validity --------------------------------------------------------------------------------


def test_expiry_follows_the_injected_clock() -> None:
    certificate = lab_certificate()
    assert describe(certificate, now=UNTIL - timedelta(seconds=1)).expired is False
    assert describe(certificate, now=UNTIL).expired is False  # the last valid instant
    assert describe(certificate, now=UNTIL + timedelta(seconds=1)).expired is True


def test_an_expired_certificate_is_reported_as_such() -> None:
    old = lab_certificate(not_before=datetime(2020, 1, 1, tzinfo=UTC), not_after=FROM)
    info = describe(old)
    assert info.expired is True
    assert info.not_after == "2026-01-01T00:00:00+00:00"
    assert info.parse_error is None


def test_a_certificate_that_is_not_valid_yet_is_not_called_expired() -> None:
    future = lab_certificate(not_before=UNTIL, not_after=UNTIL + timedelta(days=30))
    info = describe(future)
    assert info.expired is False
    assert info.not_before == "2027-01-01T00:00:00+00:00"


# -- names -----------------------------------------------------------------------------------


def test_a_name_that_is_not_in_the_certificate_does_not_match() -> None:
    certificate = lab_certificate()
    assert describe(certificate, server_name="other.test").hostname_match is False
    assert describe(certificate, server_name="lab.test").hostname_match is True
    assert describe(certificate, server_name=None).hostname_match is None


def test_an_ip_address_matches_only_an_ip_entry() -> None:
    certificate = lab_certificate()
    assert describe(certificate, server_name="127.0.0.1").hostname_match is True
    assert describe(certificate, server_name="127.0.0.2").hostname_match is False
    only_dns = lab_certificate(ip_addresses=(), dns_names=("127.0.0.1",))
    assert describe(only_dns, server_name="127.0.0.1").hostname_match is False


@pytest.mark.parametrize(
    ("pattern", "host", "expected"),
    [
        ("lab.test", "lab.test", True),
        ("LAB.test", "lab.TEST", True),
        ("lab.test.", "lab.test", True),
        ("lab.test", "lab.test.", True),
        ("lab.test", "other.test", False),
        ("lab.test", "sub.lab.test", False),
        ("*.lab.test", "www.lab.test", True),
        ("*.lab.test", "WWW.LAB.TEST", True),
        ("*.lab.test", "lab.test", False),
        ("*.lab.test", "a.b.lab.test", False),
        ("*.lab.test", ".lab.test", False),
        ("*.com", "example.com", False),  # a wildcard needs two labels after it
        ("*", "host", False),
        ("w*.lab.test", "www.lab.test", False),  # partial-label wildcards are not honoured
        ("*w.lab.test", "www.lab.test", False),
        ("a.*.test", "a.lab.test", False),
        ("*.*.test", "a.b.test", False),
        ("", "lab.test", False),
        ("lab.test", "", False),
        ("xn--bcher-kva.test", "xn--bcher-kva.test", True),
    ],
)
def test_dns_name_matching_follows_rfc_9525(pattern: str, host: str, expected: bool) -> None:
    assert hostname_matches(host, [pattern], []) is expected


def test_ipv6_server_names_compare_as_addresses() -> None:
    addresses = [ipaddress.ip_address("2001:db8::1")]
    assert hostname_matches("2001:db8::1", [], addresses) is True
    assert hostname_matches("2001:0db8:0:0:0:0:0:1", [], addresses) is True
    assert hostname_matches("2001:db8::2", [], addresses) is False


# -- self-issued and self-signature are two separate facts (decision D6) ---------------------


def test_a_self_signed_certificate_is_self_issued_and_verifies() -> None:
    info = describe(lab_certificate())
    assert (info.self_issued, info.self_signature_valid) == (True, True)


def test_a_ca_issued_leaf_is_neither() -> None:
    ca = lab_certificate(common_name="Lab CA", is_ca=True)
    leaf = lab_certificate(common_name="leaf.test", issuer=ca)
    info = describe(leaf)
    assert (info.self_issued, info.self_signature_valid) == (False, False)
    assert (info.subject, info.issuer) == ("CN=leaf.test", "CN=Lab CA")
    assert describe(ca).self_issued is True  # the CA is self-signed
    assert describe(ca).self_signature_valid is True


def test_names_that_say_self_issued_do_not_make_the_signature_verify() -> None:
    other_key = new_key()
    forged = lab_certificate(issuer_common_name="lab.test", signing_key=other_key)
    info = describe(forged)
    assert info.self_issued is True
    assert info.self_signature_valid is False


def test_a_self_signature_verifies_even_when_the_names_differ() -> None:
    odd = lab_certificate(issuer_common_name="Someone Else")  # signed with its own key
    info = describe(odd)
    assert info.self_issued is False
    assert info.self_signature_valid is True


def test_rsa_pss_signatures_are_checked() -> None:
    pss = padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=32)
    certificate = lab_certificate(key_type=KeyType.RSA, rsa_padding=pss)
    assert describe(certificate).self_signature_valid is True
    forged = lab_certificate(
        key_type=KeyType.RSA,
        rsa_padding=pss,
        issuer_common_name="lab.test",
        signing_key=new_key(KeyType.RSA),
    )
    assert describe(forged).self_signature_valid is False


def test_a_signature_made_with_another_kind_of_key_is_false_not_unknown() -> None:
    ec_ca = lab_certificate(common_name="EC CA", is_ca=True, key_type=KeyType.EC)
    rsa_ca = lab_certificate(common_name="RSA CA", is_ca=True, key_type=KeyType.RSA)
    ed_ca = lab_certificate(common_name="Ed CA", is_ca=True, key_type=KeyType.ED25519)
    cases = [
        (KeyType.RSA, ec_ca),  # an ECDSA signature under an RSA key
        (KeyType.EC, rsa_ca),  # an RSA signature under an EC key
        (KeyType.RSA, ed_ca),  # an Ed25519 signature, which has no hash, under an RSA key
        (KeyType.ED25519, rsa_ca),  # an RSA signature under an Ed25519 key
    ]
    for key_type, authority in cases:
        info = describe(
            lab_certificate(common_name="leaf.test", issuer=authority, key_type=key_type)
        )
        assert info.self_signature_valid is False, (key_type, authority.certificate.subject)


class StubCertificate:
    """A certificate whose signature algorithm the library cannot handle."""

    signature = b""
    tbs_certificate_bytes = b""
    signature_hash_algorithm = None

    def public_key(self) -> object:
        return new_key(KeyType.RSA).public_key()

    @property
    def signature_algorithm_parameters(self) -> object:
        raise UnsupportedAlgorithm("an algorithm this library does not know")


def test_an_algorithm_the_library_cannot_handle_gives_unknown() -> None:
    assert signature_verifies_under_own_key(StubCertificate()) is None  # type: ignore[arg-type]


def self_signed_der(key: PrivateKeyTypes, algorithm: hashes.HashAlgorithm | None) -> bytes:
    """A self-signed certificate for key types the lab builder does not offer."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "odd.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())  # type: ignore[arg-type]
        .serial_number(1)
        .not_valid_before(FROM)
        .not_valid_after(UNTIL)
        .sign(key, algorithm)  # type: ignore[arg-type]
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_ed448_signatures_are_checked() -> None:
    info = describe(self_signed_der(ed448.Ed448PrivateKey.generate(), None))
    assert (info.self_issued, info.self_signature_valid) == (True, True)


def test_a_key_type_that_cannot_be_checked_gives_unknown_not_false() -> None:
    info = describe(self_signed_der(dsa.generate_private_key(key_size=2048), hashes.SHA256()))
    assert info.self_issued is True
    assert info.self_signature_valid is None
    assert info.parse_error is None


def test_an_ec_certificate_on_another_curve_is_checked_too() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    assert describe(self_signed_der(key, hashes.SHA384())).self_signature_valid is True


# -- hostile and malformed input stays inside the caps ---------------------------------------


def test_no_certificate_is_data_not_an_error() -> None:
    info = describe(None)
    assert info.parse_error == NO_CERTIFICATE
    assert (info.version, info.cipher, info.sha256) == ("TLSv1.3", "TLS_AES_256_GCM_SHA384", None)
    assert info.subject is None


def test_a_certificate_over_the_size_cap_is_not_parsed() -> None:
    der = b"\x30\x82\xff\xff" + b"A" * (MAX_CERT_DER_BYTES - 3)
    assert len(der) == MAX_CERT_DER_BYTES + 1
    info = describe(der)
    assert info.parse_error == CERTIFICATE_TOO_LARGE
    assert info.sha256 == hashlib.sha256(der).hexdigest()
    assert info.subject is None


def test_garbage_of_exactly_the_size_cap_is_parsed_and_rejected() -> None:
    info = describe(b"A" * MAX_CERT_DER_BYTES)
    assert info.parse_error == MALFORMED_CERTIFICATE


@pytest.mark.parametrize(
    "der", [b"", b"\x00", b"\x30", b"\x30\x00", b"\xff" * 64, b"not a certificate"], ids=range(6)
)
def test_junk_is_reported_as_malformed(der: bytes) -> None:
    info = describe(der)
    assert info.parse_error == MALFORMED_CERTIFICATE
    assert info.sha256 == hashlib.sha256(der).hexdigest()
    assert (info.subject, info.issuer, info.self_issued, info.expired) == (None, None, None, None)


def test_every_truncation_of_a_real_certificate_is_reported_as_malformed() -> None:
    der = lab_certificate().der
    for length in range(len(der)):
        assert describe(der[:length]).parse_error == MALFORMED_CERTIFICATE, length
    assert describe(der).parse_error is None


def test_trailing_bytes_after_a_certificate_are_malformed() -> None:
    assert describe(lab_certificate().der + b"\x00").parse_error == MALFORMED_CERTIFICATE


def test_random_corruption_never_raises_and_always_gives_a_consistent_result() -> None:
    generator = random.Random(20261008)  # noqa: S311  (test data, not cryptography; fixed seed)
    der = lab_certificate(key_type=KeyType.RSA).der
    outcomes = set()
    for _ in range(400):
        mutated = bytearray(der)
        for _ in range(generator.randint(1, 4)):
            mutated[generator.randrange(len(mutated))] = generator.randrange(256)
        info = describe(bytes(mutated))
        assert info.sha256 == hashlib.sha256(bytes(mutated)).hexdigest()
        assert info.parse_error in (None, MALFORMED_CERTIFICATE)
        if info.parse_error is None:
            assert info.subject is not None
            assert len(info.subject) <= MAX_CERT_FIELD_CHARS
        else:
            assert info.subject is None
        outcomes.add(info.parse_error)
    assert MALFORMED_CERTIFICATE in outcomes  # the mutations really did break certificates


def test_a_long_subject_alternative_name_list_is_capped_but_still_used_for_matching() -> None:
    names = tuple(f"host{n:03d}.lab.test" for n in range(MAX_SAN_ENTRIES + 36))
    certificate = lab_certificate(dns_names=names, ip_addresses=())
    info = describe(certificate, server_name=names[-1])
    assert len(info.san) == MAX_SAN_ENTRIES
    assert info.san_truncated is True
    assert info.san[0] == "DNS:host000.lab.test"
    assert info.hostname_match is True  # the last name is beyond the display cap, not the match


def test_exactly_the_maximum_number_of_entries_is_not_truncated() -> None:
    names = tuple(f"h{n}.lab.test" for n in range(MAX_SAN_ENTRIES))
    info = describe(lab_certificate(dns_names=names, ip_addresses=()))
    assert (len(info.san), info.san_truncated) == (MAX_SAN_ENTRIES, False)


def test_text_from_the_certificate_is_sanitised_and_capped() -> None:
    nasty = "evil\x1b[31m\u202e\x07\x00" + "x" * 50
    certificate = lab_certificate(common_name=nasty, dns_names=("lab.test",))
    info = describe(certificate)
    assert info.subject is not None
    for text in (info.subject, info.issuer):
        assert text is not None
        assert "\x1b" not in text
        assert "\u202e" not in text
        assert "\x07" not in text
        assert "\x00" not in text
        assert len(text) <= MAX_CERT_FIELD_CHARS
    assert info.subject.startswith("CN=evil")


def test_a_very_long_name_is_cut_to_the_field_cap() -> None:
    certificate = lab_certificate(
        dns_names=("a" * 63 + "." + "b" * 63 + "." + "c" * 150 + ".test",)
    )
    info = describe(certificate)
    assert all(len(entry) <= MAX_CERT_FIELD_CHARS for entry in info.san)
    assert any(entry.endswith("...") for entry in info.san)


def test_version_and_cipher_are_sanitised_too() -> None:
    info = describe_certificate(
        None, version="TLS\x1b[0mv1", cipher="X\r\nY", server_name=None, now=NOW
    )
    assert (info.version, info.cipher) == ("TLSv1", "X  Y")
