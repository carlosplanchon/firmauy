# Setup

This guide takes you from a fresh machine to a signed and locally verified document. Run
`firmauy doctor` whenever something does not work; it checks the whole chain and needs no PIN.

## What you need

### Hardware

- A smart-card reader supported by PC/SC.
- A Uruguayan cédula with an active signing certificate.

### Operating system

- **Linux:** developed and tested primarily on Arch Linux. Debian and Ubuntu work with the same
  components; package names differ.
- **Windows (x64):** supported from 1.21.0. PC/SC is the built-in Smart Card service. The PKCS#11
  middleware is Thales Classic Client, and the 64-bit module is the one firmauy loads.
- **macOS:** not supported or tested.

### Python

Python 3.11 or newer when installing from source. `uv tool install` brings its own interpreter, so
you do not need a matching system Python for the recommended install.

## Install the smart-card stack

### Arch Linux

```bash
sudo pacman -S pcsclite ccid pcsc-tools opensc
sudo systemctl enable --now pcscd
```

`opensc` is optional: it provides `opensc-tool` for diagnostics and the OpenSC PKCS#11 backend if
you choose that path.

### Debian and Ubuntu

```bash
sudo apt update
sudo apt install pcscd pcsc-tools libpcsclite1 libccid opensc
sudo systemctl enable --now pcscd
```

If your distribution does not start `pcscd` automatically, enable and start it as shown.

### Windows

Connect the reader. Windows starts the Smart Card service (`SCardSvr`) when a reader is plugged in.
Install the cédula middleware and its driver from the official distribution. The default module is:

```text
C:\Program Files\Thales\Classic Client\BIN\gclib.dll
```

The copy under `Program Files (x86)` is 32-bit and a 64-bit Python cannot load it.

## Install the PKCS#11 middleware

The standard flow uses the Uruguayan cédula PKCS#11 module, `libgclib.so`. On Arch Linux the
community AUR package packages the official driver:

```bash
yay -S cedula-uruguay-pkcs11
```

This is a community package, not an official government package. It installs:

```text
/usr/lib/pkcs11/libgclib.so
```

Use version 7.5.0-2 or later; older versions could crash the process when a wrong PIN was entered.

If you prefer a fully open-source module, the OpenSC backend works with a development build. See
[OpenSC backend](opensc-backend.md). Native mode (`--native`) avoids the middleware entirely and
talks to the card over PC/SC.

## Install firmauy

The recommended install is an isolated CLI tool:

```bash
uv tool install firmauy
```

With pip, install into the current environment:

```bash
pip install firmauy
```

Installing the Python package does **not** install the smart-card stack. The reader service and the
PKCS#11 module, or the native path, are still required.

To update:

```bash
uv tool upgrade firmauy
```

## Check the installation

```bash
firmauy --version
firmauy doctor
```

`doctor` reports PASS, WARN or FAIL for each prerequisite and prints a remediation hint. Warnings do
not fail the command; FAILs exit with status 1. A healthy setup ends with:

```text
All checks passed.
```

For the native path, diagnose the reader and card instead of the middleware:

```bash
firmauy doctor --native
```

List what the system sees:

```bash
firmauy list-readers
firmauy list-tokens
firmauy list-certs
```

## Sign and verify a first document

Create a small PDF or use any PDF you already have. Signing prompts for the PIN and does not echo
it:

```bash
firmauy sign-pdf document.pdf
firmauy verify document_firmado.pdf
```

The default output is `document_firmado.pdf`. Verification exits with:

- `0` for VALID.
- `1` for INVALID.
- `2` for INDETERMINATE, when integrity holds but trust could not be established.

Use the Python API or `--json` if you need machine-readable results.

## Common options

### Choose the card backend

```bash
firmauy sign-pdf document.pdf --native
firmauy sign-pdf document.pdf --pkcs11-lib /path/to/libgclib.so
firmauy sign-pdf document.pdf --native --reader "ACS ACR39U 00 00"
```

`--native` needs no PKCS#11 middleware. `--reader` only applies with `--native`.

### Choose the certificate

If the token exposes more than one signing certificate:

```bash
firmauy list-certs
firmauy sign-pdf document.pdf --cert-id 0123456789abcdef
```

`--cert-id` is refused with `--native`, because the native backend has one signing certificate and
cannot honor the pinning guarantee.

### PIN sources

```bash
# Hidden prompt, the default
firmauy sign-pdf document.pdf

# Inherited file descriptor, recommended for automation
firmauy sign-pdf document.pdf --pin-source fd --pin-fd 3 3< pin.txt

# Command substitution through stdin
printf '%s\n' "$PIN" | firmauy sign-pdf document.pdf --pin-source stdin

# Environment variable
firmauy sign-pdf document.pdf --pin-source env --pin-env-var FIRMAUY_PIN
```

There is no `--pin` option. A PIN in `argv` is visible in the process list and shell history.

### Overwrite and output paths

```bash
firmauy sign-pdf document.pdf signed/document.pdf
firmauy sign-pdf document.pdf signed/document.pdf --overwrite
```

Existing output is refused without `--overwrite`, and the refusal happens before the card is
contacted.

## Troubleshooting

Run `firmauy doctor` first. The most common failures and their fixes:

| Symptom | Likely cause | Fix |
|---|---|---|
| `Could not reach the PC/SC daemon` | `pcscd` is not running | `sudo systemctl enable --now pcscd` |
| `No PC/SC readers found` | Reader not connected or not supported | Reconnect it and check `pcsc-tools` |
| `No card found in reader` | Card not inserted or not readable | Reinsert the cédula |
| `PKCS#11 module not found` | Wrong path or package missing | Install the middleware and run `doctor` |
| `No valid certificate with available private key` | Wrong card, expired certificate | Check `list-certs`; renew the card if needed |
| `Only 1 PIN try left` | Earlier wrong attempts | Unblock the cédula before retrying |
| `PIN is blocked` | Too many wrong attempts | Unblock through the issuing authority |
| Multiple readers found | More than one reader is connected | Pass `--reader` with a name from `list-readers` |
| Two card operations conflict | Another signing session holds the card | Close the other command, then retry |

Do not retry a wrong PIN blindly. Each attempt counts, and a blocked PIN requires the PUK.

## Next steps

- [Usage guide](usage.md) for every command and option.
- [Security and keys](https://github.com/carlosplanchon/firmauy/blob/main/docs/security.md) for the
  threat model and PIN handling.
- [Cookbook](cookbook.md) for automation and privacy recipes.
