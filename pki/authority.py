"""Three-level X.509 PKI for the fleet: root CA → intermediate CA → device identities.

The root signs only the intermediate (path length 1); the intermediate signs only
devices (path length 0). DPS trusts the root, the enrollment group names the
intermediate, and each device presents leaf → intermediate → root.

All keys are ECDSA P-256 with SHA-256 signatures. Private keys are written with
owner-only permissions; nothing is overwritten unless asked.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_DAYS = 3650
INTERMEDIATE_DAYS = 1825
DEVICE_DAYS = 365
CLOCK_SKEW = timedelta(minutes=5)

# DPS registration IDs: alphanumerics and - . _ :, ending in an alphanumeric or '-';
# the certificate CN (which becomes the registration and device ID) is limited to 64.
REGISTRATION_ID = re.compile(r"^[A-Za-z0-9\-._:]{0,63}[A-Za-z0-9\-]$")


class PkiError(Exception):
    """Invalid input or PKI state; the message is safe to show to the operator."""


@dataclass(frozen=True)
class Authority:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate


@dataclass(frozen=True)
class PkiLayout:
    """Where each artifact lives under the certificates directory."""

    root: Path

    @property
    def root_cert(self) -> Path:
        return self.root / "root-ca.cert.pem"

    @property
    def root_key(self) -> Path:
        return self.root / "root-ca.key.pem"

    def intermediate_cert(self, name: str) -> Path:
        return self.root / f"{name}-ca.cert.pem"

    def intermediate_key(self, name: str) -> Path:
        return self.root / f"{name}-ca.key.pem"

    def device_cert(self, device_id: str) -> Path:
        return self.root / f"{device_id}.cert.pem"

    def device_key(self, device_id: str) -> Path:
        return self.root / f"{device_id}.key.pem"

    def device_chain(self, device_id: str) -> Path:
        return self.root / f"{device_id}.fullchain.pem"

    @property
    def archive(self) -> Path:
        return self.root / "archive"


def validate_registration_id(device_id: str) -> str:
    if not REGISTRATION_ID.fullmatch(device_id):
        raise PkiError(
            f"invalid device id {device_id!r}: use 1-64 of A-Z a-z 0-9 - . _ :, "
            "ending in a letter, digit or '-'"
        )
    return device_id


def _now() -> datetime:
    return datetime.now(UTC)


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _build(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: Authority | None,
    *,
    days: int,
    path_length: int | None,
    now: datetime,
) -> x509.Certificate:
    """Sign a certificate for ``key``; ``issuer=None`` self-signs (the root)."""
    ca = path_length is not None
    signer = issuer.key if issuer else key
    not_after = now + timedelta(days=days)
    if issuer is not None:
        not_after = min(not_after, issuer.cert.not_valid_after_utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.cert.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(_key_usage(ca=ca), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        ).add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:iot:device:{subject}")]),
            critical=False,
        )
    return builder.sign(signer, hashes.SHA256())


def _pem(*certs: x509.Certificate) -> bytes:
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    data = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _refuse_overwrite(paths: list[Path], force: bool) -> None:
    existing = [str(path) for path in paths if path.exists()]
    if existing and not force:
        raise PkiError(f"refusing to overwrite {', '.join(existing)} (pass --force)")


def _load(cert_path: Path, key_path: Path, hint: str) -> Authority:
    if not cert_path.exists() or not key_path.exists():
        raise PkiError(f"{cert_path.name} not found; run '{hint}' first")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PkiError(f"{key_path} is not an EC private key")
    return Authority(key=key, cert=x509.load_pem_x509_certificate(cert_path.read_bytes()))


class Pki:
    def __init__(self, directory: Path, now=_now) -> None:
        self.layout = PkiLayout(directory)
        self._now = now

    def _root(self) -> Authority:
        return _load(self.layout.root_cert, self.layout.root_key, "python -m pki root")

    def _intermediate(self, name: str) -> Authority:
        return _load(
            self.layout.intermediate_cert(name),
            self.layout.intermediate_key(name),
            f"python -m pki intermediate {name}",
        )

    def create_root(self, common_name: str, force: bool = False) -> Path:
        _refuse_overwrite([self.layout.root_cert, self.layout.root_key], force)
        self.layout.root.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _build(common_name, key, None, days=ROOT_DAYS, path_length=1, now=self._now())
        _write_private_key(self.layout.root_key, key)
        self.layout.root_cert.write_bytes(_pem(cert))
        return self.layout.root_cert

    def create_intermediate(self, name: str, common_name: str, force: bool = False) -> Path:
        validate_registration_id(name)
        cert_path, key_path = self.layout.intermediate_cert(name), self.layout.intermediate_key(name)
        _refuse_overwrite([cert_path, key_path], force)
        root = self._root()
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _build(common_name, key, root, days=INTERMEDIATE_DAYS, path_length=0, now=self._now())
        _write_private_key(key_path, key)
        cert_path.write_bytes(_pem(cert))
        return cert_path

    def issue_device(self, device_id: str, issuer: str, *, rotate: bool = False, force: bool = False) -> Path:
        """Issue a device identity. ``rotate`` archives the current one and issues a new key, same CN."""
        validate_registration_id(device_id)
        paths = [
            self.layout.device_key(device_id),
            self.layout.device_cert(device_id),
            self.layout.device_chain(device_id),
        ]
        if rotate:
            if not paths[1].exists():
                raise PkiError(f"no certificate for {device_id} to rotate")
            self._archive(device_id, paths)
        else:
            _refuse_overwrite(paths, force)
        root, intermediate = self._root(), self._intermediate(issuer)
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _build(device_id, key, intermediate, days=DEVICE_DAYS, path_length=None, now=self._now())
        key_path, cert_path, chain_path = paths
        _write_private_key(key_path, key)
        cert_path.write_bytes(_pem(cert))
        chain_path.write_bytes(_pem(cert, intermediate.cert, root.cert))
        return chain_path

    def _archive(self, device_id: str, paths: list[Path]) -> None:
        stamp = self._now().strftime("%Y%m%dT%H%M%SZ")
        target = self.layout.archive / f"{device_id}-{stamp}"
        target.mkdir(parents=True, exist_ok=False)
        for path in paths:
            if path.exists():
                path.replace(target / path.name)

    def check_device(self, device_id: str) -> x509.Certificate:
        """Verify the device chain as a TLS client verifier would; raise PkiError if it fails."""
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

        chain_path = self.layout.device_chain(device_id)
        if not chain_path.exists():
            raise PkiError(f"{chain_path.name} not found")
        leaf, *intermediates = x509.load_pem_x509_certificates(chain_path.read_bytes())
        store = Store(x509.load_pem_x509_certificates(self.layout.root_cert.read_bytes()))
        verifier = PolicyBuilder().store(store).time(self._now()).build_client_verifier()
        try:
            verifier.verify(leaf, intermediates)
        except VerificationError as exc:
            raise PkiError(f"{device_id}: chain does not verify: {exc}") from exc
        if leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != device_id:
            raise PkiError(f"{device_id}: certificate CN does not match the device id")
        return leaf


def certificate_der_base64(pem_path: Path) -> str:
    """Single-line base64 DER of the first certificate in a PEM file (the ARM certificate format)."""
    import base64

    cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
