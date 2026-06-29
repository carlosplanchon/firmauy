"""CLI-level smoke tests (Typer app wiring)."""

from importlib.metadata import version

from typer.testing import CliRunner

from cedula_uy_pdf_sign.cli import app

runner = CliRunner()


def test_version_flag_reports_package_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"firmauy {version('cedula-uy-pdf-sign')}" in result.output


def test_help_still_shows_app_description():
    # The --version callback must not clobber the app's help text.
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Sign and verify PDF (PAdES)" in result.output
    assert "--version" in result.output
