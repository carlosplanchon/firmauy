# Changelog

User-facing strings are a public surface: firmauy-desktop translates them by their exact text. An
entry that adds, changes or removes one lists it verbatim, with `{placeholders}` where the text is
filled in at run time.

## 1.21.0

### Windows support

Signing, `doctor` and the native PC/SC backend now work on Windows (x64). Linux behaviour, output and
strings are unchanged. macOS is not covered by this release.

- **Signed output is written on Windows.** Every signature used to fail at the commit, after the
  PIN had been entered and the card had signed: on Windows `os` has no `O_CLOEXEC`, `O_NOFOLLOW` or
  `O_NONBLOCK`, and Windows will not rename, link or delete a file that is still open. The staging
  file is now closed before the commit and before any cleanup, and no `.firmauy-*.part` is left
  behind after a failure. The cleanup waits up to a second for another program, such as a virus
  scanner, to let go of the staging file. Staging and input files are opened with `O_BINARY`, so no
  `\n` becomes `\r\n` on the way.
- **The guarantees that hold on Windows:** the commit is atomic, a symlink at the output is
  replaced rather than written through, and `overwrite=False` still refuses an existing file, a
  file that appears while signing, and a dangling symlink (`os.link` on NTFS). On FAT32 and exFAT,
  which have no hard links, the same reservation fallback as on Linux is used. `--input-dir` still
  refuses a file that was swapped for another file or a link after it was listed.
- **What Windows gives up:** there is no POSIX access control. The signed file inherits its folder's
  NTFS permissions like any new file there, nothing is carried over from a file it replaces, and
  there is no 0600 window while it is written. So on Windows `OutputAccessControlError` and
  `OutputCommittedError` are never raised, and the `chmod u+r` advice never appears.
- **`DEFAULT_PKCS11_LIB`** on Windows is `%ProgramFiles%\Thales\Classic Client\BIN\gclib.dll`
  (Thales Classic Client), so a 64-bit Python gets the 64-bit module. Unchanged elsewhere:
  `/usr/lib/pkcs11/libgclib.so`.
- **The national CA cache** lives in `%LOCALAPPDATA%\firmauy\national-ca` on Windows. Unchanged
  elsewhere: `$XDG_CACHE_HOME/firmauy/national-ca`, or `~/.cache/firmauy/national-ca`.
- **`doctor` checks the Smart Card service (SCardSvr)** on Windows instead of pcscd. The check
  passes when PC/SC can list readers. A stopped service is not a finding: Windows starts it when a
  reader is plugged in. No check suggests a Linux command on Windows.
- CI runs the suite on `windows-latest` with Python 3.11 and 3.14.

#### New strings (Windows only)

`doctor` row, shown on Windows in place of `pcscd running`:

- `Smart Card service available`

Its detail on a WARN is the PC/SC error as pyscard reports it.

`doctor` fix texts:

- `Connect the reader; Windows starts the Smart Card service (SCardSvr) on its own.`
  (`Smart Card service available`, and `PC/SC reader detected` when listing readers fails)
- `Connect a reader and check that Windows lists it under "Smart card readers" in Device Manager.`
  (`PC/SC reader detected`, none found)
- `Install Thales Classic Client (the cédula middleware), or pass --pkcs11-lib.`
  (`PKCS#11 module present`)
- `A 64-bit Python cannot load the 32-bit gclib.dll. Use the 64-bit one: {default module path}`
  (`PKCS#11 module present` for a path under `Program Files (x86)`, and `PKCS#11 module loads` for
  a 32-bit module, recognised by its PE header)
- `Insert the cédula and check the reader connection / Smart Card service.`
  (`cédula token detected`)

Errors and messages:

- `PC/SC reader support (pyscard) could not be loaded. Reinstall firmauy.`
- `Could not reach the Smart Card service ({error}). Connect the reader; Windows starts the Smart Card service (SCardSvr) on its own.`
- `No PC/SC readers found. Is a reader connected?` (also printed by `list-readers`)

#### Strings no longer shown on Windows

All are unchanged on Linux.

- The `pcscd running` row, with its details `installed but not running` and `not found` and its
  fixes `Start it: sudo systemctl enable --now pcscd` and
  `Install the smart-card stack: sudo pacman -S pcsclite ccid`
- `Install the middleware (Arch: yay -S cedula-uruguay-pkcs11), or pass --pkcs11-lib.`
- `Insert the cédula and check the reader connection / pcscd.`
- `Install the smart-card stack (sudo pacman -S pcsclite ccid) and start pcscd.`
- `Connect a reader and make sure pcscd is running.`
- `PC/SC reader support could not be loaded. Install the smart-card stack and start pcscd (Arch: sudo pacman -S pcsclite ccid; sudo systemctl enable --now pcscd).`
- `Could not reach the PC/SC daemon ({error}). Is pcscd running? (Arch: sudo systemctl enable --now pcscd)`
- `No PC/SC readers found. Is pcscd running and a reader connected?`

#### Changed strings on Linux

None.
