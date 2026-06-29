import io

import pytest
import typer

from cedula_uy_pdf_sign.pin import PinSource, get_pin


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


class TestGetPinEmpty:
    @pytest.mark.parametrize("raw", ["\n", "\r\n", ""])  # blank line / CRLF / EOF
    def test_empty_pin_from_stdin_raises(self, monkeypatch, raw):
        monkeypatch.setattr("sys.stdin", io.StringIO(raw))
        with pytest.raises(RuntimeError, match="Empty PIN"):
            get_pin(PinSource.stdin, env_var=None, fd=None)
