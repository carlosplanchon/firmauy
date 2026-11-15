# Development

The project uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

```bash
# Clone the repository
git clone https://github.com/carlosplanchon/firmauy.git
cd firmauy

# Create the environment and install dependencies (runtime + dev)
uv sync

# Run the test suite (PKCS#11 integration tests need SoftHSM2, see below)
uv run pytest

# Run the CLI from the working tree
uv run firmauy --help
```

The package source lives under `src/firmauy/`; tests under `tests/`.

## Documentation site

The documentation is built with [Zensical](https://zensical.org/). Spanish is the default site and
English is an `/en/` mirror. The two builds share the same content sources: `docs-es/` for Spanish
and `docs/` for English.

```bash
# Install the pinned generator (the workflow uses the same version)
pip install zensical==0.0.45

# Spanish, the default: builds into site/
zensical build --clean

# English: builds into site/en/
zensical build -f zensical.en.toml

# Local preview
zensical serve
```

Run both builds before opening a documentation pull request. Zensical validates internal links and
anchors; a clean build reports `No issues found`. The GitHub Actions workflow in
`.github/workflows/docs.yml` publishes `site/` to GitHub Pages.

When you add a page, add it to the navigation in `zensical.toml` and `zensical.en.toml`, and provide
the counterpart in the other language. Keep the two trees in sync.

## Developing without the real card (SoftHSM2)

Entering the wrong PIN too many times **blocks the cédula**, so you should not develop against the real card. Instead, you can run the full signing pipeline against a software PKCS#11 token (SoftHSM2) that mimics a cédula closely enough to exercise token discovery, certificate selection, PIN handling and signing.

```bash
# Arch Linux: install the software token + tooling
sudo pacman -S softhsm opensc openssl

# Provision a throwaway "fake cédula" token under ./.softhsm
bash scripts/dev-softhsm-setup.sh
```

The script prints ready-to-run `firmauy list-certs` / `firmauy sign-pdf` commands pointing at the SoftHSM module. The resulting PDF is a cryptographically valid signature, but it will **not** validate as a *cédula* signature on [firma.gub.uy](https://firma.gub.uy/) (the issuing CA is a local fake, by design). Reset everything with `rm -rf .softhsm`.

The token persists under `.softhsm`, so this doubles as a normal development loop: run `firmauy` by hand as often as you like (signing test PDFs, trying signature positions with `--x1/--y1/...`, exercising `sign-pdf-batch`, reproducing a reported bug) while iterating on the code, without the card and without risking PIN lockout. The real card is then only needed for a final validation run and for middleware-specific behaviour.

The same setup powers the end-to-end integration tests (`tests/test_integration_pkcs11.py`, `test_integration_xades.py`, `test_integration_cms.py`) that exercise the real PKCS#11 path: signing PDF (PAdES), XML (XAdES) and arbitrary files (CAdES/.p7s) plus cryptographic verification of the result, and the selection/error branches that are unsafe to reproduce on the real card (expired certificate, certificate without a private key, multiple tokens, certificate scoring and `--cert-id` override). They are **skipped automatically** when SoftHSM2 / OpenSC / OpenSSL (or signxml) are not installed, so `uv run pytest` works either way.
