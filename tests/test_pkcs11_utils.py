import datetime
from contextlib import contextmanager

import pkcs11
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from firmauy.errors import (
    CertificateNotFoundError,
    CertificateNotValidError,
    IncorrectPinError,
    PinError,
    PinLockedError,
)
from firmauy.pkcs11_utils import (
    cert_is_expired,
    cert_not_yet_valid,
    check_certificate_before_login,
    check_pin_status,
    has_private_key,
    login_session,
    normalize_cert_id_hex,
    read_certificates,
    token_to_dict,
    usable_certificates,
)


class _FakeSession:
    def __init__(self, items=(), error=None):
        self.items = items
        self.error = error

    def get_objects(self, query):
        if self.error is not None:
            raise self.error
        return iter(self.items)


class TestHasPrivateKey:
    def test_true_when_present(self):
        assert has_private_key(_FakeSession(items=[object()]), b"\x01") is True

    def test_false_when_absent(self):
        assert has_private_key(_FakeSession(items=[]), b"\x01") is False

    def test_propagates_errors_instead_of_swallowing(self):
        # A genuine PKCS#11 error must surface, not be hidden as "no key" (which could drop the
        # only usable certificate).
        with pytest.raises(RuntimeError, match="device error"):
            has_private_key(_FakeSession(error=RuntimeError("device error")), b"\x01")


class TestNormalizeCertIdHex:
    def test_clean_hex_uppercased(self):
        assert normalize_cert_id_hex("abcdef") == "ABCDEF"

    def test_already_uppercase(self):
        assert normalize_cert_id_hex("ABCDEF") == "ABCDEF"

    def test_strips_colons(self):
        assert normalize_cert_id_hex("ab:cd:ef") == "ABCDEF"

    def test_strips_spaces(self):
        assert normalize_cert_id_hex("ab cd ef") == "ABCDEF"

    def test_strips_colons_and_spaces(self):
        assert normalize_cert_id_hex("ab: cd :ef") == "ABCDEF"

    def test_digits_only(self):
        assert normalize_cert_id_hex("0123456789") == "0123456789"

    def test_invalid_raises_bad_parameter(self):
        with pytest.raises(ValueError):
            normalize_cert_id_hex("zz")

    def test_empty_raises_bad_parameter(self):
        with pytest.raises(ValueError):
            normalize_cert_id_hex("")

    def test_odd_length_raises_bad_parameter(self):
        # Valid hex characters but an odd count: a byte ID is always even-length. This used to slip
        # through and blow up later in bytes.fromhex with a cryptic ValueError.
        with pytest.raises(ValueError, match="odd number"):
            normalize_cert_id_hex("abc")

    def test_odd_length_with_separators_raises(self):
        with pytest.raises(ValueError, match="odd number"):
            normalize_cert_id_hex("ab:c")


class TestCertIsExpired:
    def test_valid_cert_not_expired(self, cert_valid):
        assert cert_is_expired(cert_valid) is False

    def test_expired_cert_is_expired(self, cert_expired):
        assert cert_is_expired(cert_expired) is True


def _future_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FUTURE")])
    return (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now + datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=380))
        .sign(key, hashes.SHA256())
    )


class TestCertNotYetValid:
    def test_currently_valid_cert_is_not_future(self, cert_valid):
        assert cert_not_yet_valid(cert_valid) is False

    def test_future_cert_is_not_yet_valid(self):
        cert = _future_cert()
        assert cert_not_yet_valid(cert) is True
        assert cert_is_expired(cert) is False   # future != expired


class TestTokenToDict:
    def test_maps_attributes_and_nulls_empty(self):
        from types import SimpleNamespace

        tok = SimpleNamespace(
            label="  test-cedula ", manufacturer="ACME", model="", serial="   ",
        )
        assert token_to_dict(tok) == {
            "label": "test-cedula", "manufacturer": "ACME", "model": None, "serial": None,
        }

    def test_missing_attributes_become_none(self):
        from types import SimpleNamespace

        assert token_to_dict(SimpleNamespace()) == {
            "label": None, "manufacturer": None, "model": None, "serial": None,
        }

    def test_a_bytes_attribute_is_decoded_not_left_as_bytes(self):
        """Real finding against a Gemalto middleware: it returns the serial as the raw PKCS#11
        attribute, so the annotated str was really bytes and a caller formatting it printed the
        Python repr, b'66000034D0201077'. NUL padding is the attribute format, not the value."""
        from types import SimpleNamespace

        tok = SimpleNamespace(label=b"GemP15-1\x00\x00", manufacturer=b"  ",
                              model="Classic V4", serial=b"66000034D0201077")

        assert token_to_dict(tok) == {
            "label": "GemP15-1",
            "manufacturer": None,      # padding only, so it reads as absent
            "model": "Classic V4",
            "serial": "66000034D0201077",
        }


# --- what can be checked before the PIN ---------------------------------------------------------

def _cert_object(cert, obj_id=b"\x01"):
    """A certificate object as python-pkcs11 hands it over: attributes looked up by key."""
    return {pkcs11.Attribute.ID: obj_id,
            pkcs11.Attribute.VALUE: cert.public_bytes(serialization.Encoding.DER)}


class _FakeToken:
    """A token reporting ``flags`` as its PIN state, opening ``session`` (or failing with
    ``open_error``), and recording the PIN of every session it opens (None for no login)."""

    def __init__(self, session=None, *, flags=0, open_error=None):
        self.session = session if session is not None else _FakeSession()
        self.flags = pkcs11.TokenFlag(flags)
        self.open_error = open_error
        self.logins = []

    @contextmanager
    def open(self, user_pin=None):
        self.logins.append(user_pin)
        if self.open_error is not None:
            raise self.open_error
        yield self.session


def _not_yet_valid() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Juan Test")])
    return (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=400))
        .sign(key, hashes.SHA256())
    )


class TestReadCertificates:
    def test_parses_what_it_can_and_counts_the_rest(self, cert_valid):
        items = [
            _cert_object(cert_valid, b"\x01"),
            {pkcs11.Attribute.ID: b"\x02", pkcs11.Attribute.VALUE: b"not a certificate"},
            {pkcs11.Attribute.ID: b"\x03"},              # a value that cannot be read
        ]
        certs, unreadable = read_certificates(_FakeSession(items=items))

        assert [obj_id for obj_id, _ in certs] == [b"\x01"]
        assert unreadable == 2


class TestUsableCertificates:
    def test_splits_the_valid_from_the_expired(self, cert_valid, cert_expired):
        valid, unusable = usable_certificates(
            [(b"\x01", cert_valid), (b"\x02", cert_expired)], None)

        assert [obj_id for obj_id, _ in valid] == [b"\x01"]
        assert [obj_id for obj_id, _ in unusable] == [b"\x02"]

    def test_keeps_only_the_requested_id(self, cert_valid):
        valid, _ = usable_certificates([(b"\x01", cert_valid), (b"\x02", cert_valid)], "02")

        assert [obj_id for obj_id, _ in valid] == [b"\x02"]

    # The messages select_certificate has always raised, now raised from here.
    def test_an_unknown_id_is_not_found(self, cert_valid):
        with pytest.raises(CertificateNotFoundError, match="No certificate found with ID 02 "):
            usable_certificates([(b"\x01", cert_valid)], "02")

    def test_no_certificates_are_not_found(self):
        with pytest.raises(CertificateNotFoundError, match="No usable certificates found"):
            usable_certificates([], None)

    def test_only_expired_ones_are_not_valid(self, cert_expired):
        with pytest.raises(CertificateNotValidError, match="is expired .*: Juan Test"):
            usable_certificates([(b"\x01", cert_expired)], None)

    def test_only_future_ones_are_not_valid(self):
        with pytest.raises(CertificateNotValidError, match="is not yet valid"):
            usable_certificates([(b"\x01", _not_yet_valid())], None)


class TestCheckCertificateBeforeLogin:
    def test_an_expired_certificate_is_refused_without_a_login(self, cert_expired):
        token = _FakeToken(_FakeSession(items=[_cert_object(cert_expired)]))

        with pytest.raises(CertificateNotValidError, match="expired"):
            check_certificate_before_login(token, None)
        assert token.logins == [None]

    def test_an_unknown_cert_id_is_refused_without_a_login(self, cert_valid):
        token = _FakeToken(_FakeSession(items=[_cert_object(cert_valid, b"\x01")]))

        with pytest.raises(CertificateNotFoundError, match="02"):
            check_certificate_before_login(token, "02")
        assert token.logins == [None]

    def test_a_valid_certificate_passes(self, cert_valid):
        token = _FakeToken(_FakeSession(items=[_cert_object(cert_valid)]))

        check_certificate_before_login(token, None)
        assert token.logins == [None]

    def test_a_token_showing_nothing_concludes_nothing(self):
        # Its certificates may only appear after login, where select_certificate still decides.
        check_certificate_before_login(_FakeToken(_FakeSession(items=[])), "02")

    def test_an_unreadable_certificate_concludes_nothing(self, cert_expired):
        # The object it could not read might be the valid certificate.
        items = [_cert_object(cert_expired, b"\x01"), {pkcs11.Attribute.ID: b"\x02"}]

        check_certificate_before_login(_FakeToken(_FakeSession(items=items)), None)

    @pytest.mark.parametrize("failure", ["open", "list"])
    def test_a_module_error_concludes_nothing(self, failure):
        error = pkcs11.exceptions.GeneralError()
        token = (_FakeToken(open_error=error) if failure == "open"
                 else _FakeToken(_FakeSession(error=error)))

        check_certificate_before_login(token, None)


class TestCheckPinStatus:
    def test_a_locked_pin_is_refused(self):
        with pytest.raises(PinLockedError):
            check_pin_status(_FakeToken(flags=pkcs11.TokenFlag.USER_PIN_LOCKED))

    def test_the_final_try_is_refused(self):
        with pytest.raises(PinError, match="Only 1 PIN try left") as exc:
            check_pin_status(_FakeToken(flags=pkcs11.TokenFlag.USER_PIN_FINAL_TRY))
        assert type(exc.value) is PinError

    def test_a_low_count_alone_is_not_refused(self):
        check_pin_status(_FakeToken(flags=pkcs11.TokenFlag.USER_PIN_COUNT_LOW))

    def test_a_token_reporting_nothing_is_not_refused(self):
        check_pin_status(_FakeToken())


class TestLoginSession:
    def test_logs_in_with_the_pin_given(self):
        token = _FakeToken()

        with login_session(token, "1234") as session:
            assert session is token.session
        assert token.logins == ["1234"]

    @pytest.mark.parametrize("raised, expected", [
        (pkcs11.exceptions.PinIncorrect, IncorrectPinError),
        (pkcs11.exceptions.PinLocked, PinLockedError),
    ], ids=["incorrect", "locked"])
    def test_translates_the_module_pin_errors(self, raised, expected):
        with pytest.raises(expected):
            with login_session(_FakeToken(open_error=raised()), "1234"):
                pass
