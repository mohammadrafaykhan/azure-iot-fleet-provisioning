import os
import sys
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.__main__ import main as pki_main
from pki.authority import Pki, PkiError, certificate_der_base64, validate_registration_id


@pytest.fixture
def pki(tmp_path):
    authority = Pki(tmp_path)
    authority.create_root("Test Root CA")
    authority.create_intermediate("devices", "Test Devices CA")
    return authority


def _certs(path):
    return x509.load_pem_x509_certificates(path.read_bytes())


def test_chain_is_leaf_intermediate_root_and_verifies(pki):
    chain = _certs(pki.issue_device("press-01", "devices"))
    assert [c.subject.rfc4514_string() for c in chain] == [
        "CN=press-01",
        "CN=Test Devices CA",
        "CN=Test Root CA",
    ]
    assert pki.check_device("press-01").subject.rfc4514_string() == "CN=press-01"


def test_path_lengths_restrict_who_can_sign(pki):
    root = _certs(pki.layout.root_cert)[0]
    intermediate = _certs(pki.layout.intermediate_cert("devices"))[0]
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0


def test_device_certificate_profile(pki):
    pki.issue_device("press-01", "devices")
    leaf = _certs(pki.layout.device_cert("press-01"))[0]
    assert isinstance(leaf.public_key(), ec.EllipticCurvePublicKey)
    assert leaf.public_key().curve.name == "secp256r1"
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_cert_sign


def test_leaf_never_outlives_its_issuer(tmp_path):
    clock = {"now": datetime(2026, 1, 1, tzinfo=UTC)}
    pki = Pki(tmp_path, now=lambda: clock["now"])
    pki.create_root("Root")
    pki.create_intermediate("devices", "Devices")
    clock["now"] += timedelta(days=1700)
    pki.issue_device("press-01", "devices")
    leaf = _certs(pki.layout.device_cert("press-01"))[0]
    intermediate = _certs(pki.layout.intermediate_cert("devices"))[0]
    assert leaf.not_valid_after_utc <= intermediate.not_valid_after_utc


def test_refuses_to_overwrite_without_force(pki):
    pki.issue_device("press-01", "devices")
    with pytest.raises(PkiError, match="refusing to overwrite"):
        pki.issue_device("press-01", "devices")
    pki.issue_device("press-01", "devices", force=True)


def test_rotation_archives_old_identity_and_keeps_device_id(pki):
    pki.issue_device("press-01", "devices")
    old = _certs(pki.layout.device_cert("press-01"))[0]
    pki.issue_device("press-01", "devices", rotate=True)
    new = _certs(pki.layout.device_cert("press-01"))[0]
    assert new.subject == old.subject
    assert new.public_key().public_numbers() != old.public_key().public_numbers()
    archived = list(pki.layout.archive.glob("press-01-*/press-01.cert.pem"))
    assert len(archived) == 1
    pki.check_device("press-01")


def test_rotate_requires_existing_identity(pki):
    with pytest.raises(PkiError, match="no certificate"):
        pki.issue_device("press-09", "devices", rotate=True)


def test_check_fails_for_a_chain_from_another_root(tmp_path, pki):
    other = Pki(tmp_path / "other")
    other.create_root("Other Root")
    other.create_intermediate("devices", "Other Devices")
    other.issue_device("press-01", "devices")
    pki.layout.device_chain("press-01").write_bytes(other.layout.device_chain("press-01").read_bytes())
    with pytest.raises(PkiError, match="does not verify"):
        pki.check_device("press-01")


def test_missing_ca_gives_actionable_error(tmp_path):
    with pytest.raises(PkiError, match="python -m pki root"):
        Pki(tmp_path).create_intermediate("devices", "Devices")


@pytest.mark.parametrize("device_id", ["press-01", "line1.press_02", "a", "plant:7-", "x" * 64])
def test_valid_registration_ids(device_id):
    assert validate_registration_id(device_id) == device_id


@pytest.mark.parametrize("device_id", ["", "bad id", "press-01.", "x" * 65, "press/01", "pr€ss"])
def test_invalid_registration_ids(device_id):
    with pytest.raises(PkiError):
        validate_registration_id(device_id)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_keys_are_owner_only(pki):
    pki.issue_device("press-01", "devices")
    for path in (pki.layout.root_key, pki.layout.device_key("press-01")):
        assert os.stat(path).st_mode & 0o077 == 0


def test_der_output_is_single_line_base64(pki):
    value = certificate_der_base64(pki.layout.root_cert)
    assert "\n" not in value and not value.startswith("-----")


def test_cli_end_to_end_and_exit_codes(tmp_path, capsys):
    base = ["--dir", str(tmp_path)]
    assert pki_main([*base, "root"]) == 0
    assert pki_main([*base, "intermediate", "devices"]) == 0
    assert pki_main([*base, "device", "press-01", "press-02"]) == 0
    assert pki_main([*base, "check", "press-01", "press-02"]) == 0
    assert pki_main([*base, "device", "press-01"]) == 2
    assert pki_main([*base, "device", "bad id"]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
