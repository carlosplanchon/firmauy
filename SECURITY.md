# Security Policy

FirmaUY signs documents with the Uruguayan national ID card and handles the card's PIN. Security
reports are taken seriously, within the limits of a community project. Thank you for reporting
responsibly.

For the design behind these limits, including how the private key stays on the card, how the PIN
and retry counter are protected, and which threats are out of scope, read
[Security and key handling](docs/security.md).

## Reporting a vulnerability

Please do **not** open a public issue or pull request for a security problem.

Report it privately through GitHub's private vulnerability reporting:

- Go to <https://github.com/carlosplanchon/firmauy/security/advisories/new>, or the repository's
  **Security** tab, then **Report a vulnerability**.
- If that is not possible, email **carlosplanchon@cognitialabs.com** with `[SECURITY]` in the
  subject.

Include what you can: a description, steps to reproduce, a proof of concept, the affected version
and your assessment of the impact. Reports in Spanish or English are equally welcome.

## What counts

Especially relevant areas, in rough order of severity:

- **Verification bypass**: anything that makes `verify` (or the verify commands) report VALID for
  a signature that should not validate, including trust-chain validation flaws.
- **Signature forgery or misuse** of the signing paths.
- **PIN exposure**: any path that lands the PIN in argv, logs, files, exception text or results,
  or that spends card PIN retries in unexpected ways.
- **Card damage**: native-mode APDU sequences that could block or corrupt the card.
- **Release integrity**: anything affecting the supply chain of the `firmauy` package on PyPI.

Out of scope here (report upstream instead):

- The cédula card or its applet, AGESIC services, and the official validator.
- The proprietary PKCS#11 middleware.
- The cédula driver inside OpenSC: report through
  [OpenSC's security process](https://github.com/OpenSC/OpenSC/security).
- Issues that require an already-compromised machine.

## What to expect

This is a community project with a single maintainer, so the process is honest rather than
corporate:

- Acknowledgment within **7 days**.
- An assessment and, when confirmed, a fix released as soon as practical, coordinated with you.
- Public disclosure through a GitHub security advisory once a fix is available, with credit to
  the reporter unless you prefer otherwise.

Only the **latest release on PyPI** receives security fixes.

FirmaUY is experimental and not officially certified (see the README's legal section). That
context does not lower the bar: a verification bypass or PIN exposure is treated as critical.
