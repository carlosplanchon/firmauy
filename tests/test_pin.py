import io

import pytest
import typer

from firmauy.pin import PinSource, get_pin


class TestGetPinEnv:
    def test_returns_value_from_env(self, monkeypatch):
        monkeypatch.setenv("MI_PIN", "1234")
        assert get_pin(PinSource.env, env_var="MI_PIN", fd=None) == "1234"

    def test_raises_if_env_var_not_set(self, monkeypatch):
        monkeypatch.delenv("PIN_INEXISTENTE", raising=False)
        with pytest.raises(RuntimeError, match="is not defined or empty"):
            get_pin(PinSource.env, env_var="PIN_INEXISTENTE", fd=None)

    def test_raises_if_env_var_name_not_provided(self):
        with pytest.raises(typer.BadParameter):
            get_pin(PinSource.env, env_var=None, fd=None)


class TestGetPinFd:
    def test_raises_if_fd_not_provided(self):
        with pytest.raises(typer.BadParameter):
            get_pin(PinSource.fd, env_var=None, fd=None)


class TestGetPinStdin:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("1234\n", "1234"),       # unix newline
            ("1234\r\n", "1234"),     # windows CRLF
            ("1234", "1234"),         # no trailing newline
        ],
    )
    def test_strips_trailing_newlines(self, monkeypatch, raw, expected):
        monkeypatch.setattr("sys.stdin", io.StringIO(raw))
        assert get_pin(PinSource.stdin, env_var=None, fd=None) == expected

    def test_tty_uses_getpass_to_suppress_echo(self, monkeypatch, capsys):
        # When stdin is a TTY, the PIN must not echo to the screen, and the retry-limit
        # warning must show exactly as with --pin-source prompt.
        stdin = io.StringIO("")
        monkeypatch.setattr("sys.stdin", stdin)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)

        calls = []
        monkeypatch.setattr("getpass.getpass", lambda prompt: calls.append(prompt) or "5678")

        assert get_pin(PinSource.stdin, env_var=None, fd=None) == "5678"
        assert calls == ["Cédula PIN: "]
        assert "retry limit" in capsys.readouterr().err


class TestGetPinEmpty:
    @pytest.mark.parametrize("raw", ["\n", "\r\n", ""])  # blank line / CRLF / EOF
    def test_empty_pin_from_stdin_raises(self, monkeypatch, raw):
        monkeypatch.setattr("sys.stdin", io.StringIO(raw))
        with pytest.raises(RuntimeError, match="Empty PIN"):
            get_pin(PinSource.stdin, env_var=None, fd=None)


# --- what never reaches the card ----------------------------------------------
#
# A wrong PIN is not free. The cédula allows a handful of tries and then blocks, and unblocking
# means going somewhere in person. So anything the card could not possibly accept is refused
# here, at no cost, rather than spent as an attempt. Both backends come through this one
# function: the native path used to check the length and the encoding, let letters through, and
# tell the user in the same message that a PIN must be digits.

class TestResolveFinalPin:
    def _resolve(self, value):
        from firmauy.signing import _resolve_final_pin

        return _resolve_final_pin(value, None)

    def test_a_plain_pin_passes(self):
        assert self._resolve("1234") == "1234"
        assert self._resolve("12345678") == "12345678"

    def test_letters_never_reach_the_card(self):
        from firmauy.errors import PinError

        with pytest.raises(PinError, match="digits only"):
            self._resolve("abcd")

    def test_a_typo_that_slips_one_letter_in_is_caught(self):
        """The realistic case, and the one that cost an attempt: a finger off by one key."""
        from firmauy.errors import PinError

        with pytest.raises(PinError, match="digits only"):
            self._resolve("12e4")

    def test_digits_that_are_not_ascii_are_refused(self):
        """str.isdigit() is true for these and the card would never take them. Without the ascii
        check the encode one layer down would raise instead, past this guard."""
        from firmauy.errors import PinError

        for exotic in ("١٢٣٤", "①②③④"):
            with pytest.raises(PinError, match="digits only"):
                self._resolve(exotic)

    def test_too_short_and_too_long_are_refused(self):
        from firmauy.errors import PinError

        with pytest.raises(PinError, match="4 to 8 digits"):
            self._resolve("123")
        with pytest.raises(PinError, match="4 to 8 digits"):
            self._resolve("123456789")

    def test_an_empty_pin_still_says_empty(self):
        """It has its own message, because the likely cause differs: an unset variable or an
        empty file, not a typo."""
        from firmauy.errors import PinError

        with pytest.raises(PinError, match="Empty PIN"):
            self._resolve("")

    def test_the_provider_is_validated_too(self):
        """The CLI's --pin-source handling arrives as a callback, and it is not exempt."""
        from firmauy.errors import PinError
        from firmauy.signing import _resolve_final_pin

        with pytest.raises(PinError, match="digits only"):
            _resolve_final_pin(None, lambda: "no-soy-un-pin")

    @pytest.mark.parametrize("value", ["", "abcd", "12e4", "١٢٣٤", "123", "123456789"],
                             ids=["empty", "letters", "typo", "arabic-indic", "short", "long"])
    def test_every_refusal_here_is_a_format_error(self, value):
        """The class says what fixes it: typing the PIN again. The last-try refusal needs the card
        unblocked instead, and was the same bare PinError until 1.20.0, which left a GUI telling
        the two apart by whether its prompt had run."""
        from firmauy.errors import PinFormatError

        with pytest.raises(PinFormatError) as exc:
            self._resolve(value)
        assert type(exc.value) is PinFormatError
