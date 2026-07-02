# Uruguayan cédula (chip): card protocol reference

Card-level facts and the APDU-level signing protocol for the Uruguayan national eID card (cédula de
identidad con chip). This documents **only the card**: no middleware, drivers, or client software.
It is the reference behind FirmaUY's native, PKCS#11-free signing backend (`--native`, implemented in
`src/firmauy/native_card.py`), and is built from public information only:

- the official AGESIC technical documentation ("documentación técnica cédula identidad chip",
  *documentación técnica 9*), which gives the data model, the signing sequence and the declared
  algorithm set, and
- the standard **ISO/IEC 7816-4 IAS-ECC** command set the card implements.

The exact byte sequence and the card's status-word behaviour were then confirmed empirically by
running FirmaUY against a cardholder's **own** card. Nothing here comes from disassembling,
intercepting or reverse-engineering the proprietary middleware. It is the documented, standard smart
card interface exercised directly.

Sources:
- <https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/documentacion-tecnica-id-uruguay/documentacion-tecnica-id-uruguay-9>

> This project is not affiliated with or endorsed by AGESIC, and the native backend is experimental
> and not officially certified. See the [README](../README.md#legal-and-compliance).

## What the card is

- Gemalto **IAS Classic v4** (hybrid cards) or **v5** (2022 dual-interface / NFC generation), on the
  MultiApp platform.
- Standard **PKCS#15** file structure layered on the IAS-ECC applet.
- **RSA-2048** signing key. Read-only government eID (no object writes).
- Signing is standard IAS-ECC: `VERIFY PIN → MSE:SET DST → PSO:HASH → PSO:CDS`.

| Field | Value |
|---|---|
| ATR (a v4 sample) | `3B 7F 96 00 00 80 31 80 65 B0 85 05 00 11 12 0F FF 82 90 00` |
| Platform | Gemalto IAS Classic v4 / v5, MultiApp |
| Key | RSA-2048 |
| Interfaces | contact, and v5 adds contactless (NFC, PACE) |

Serial number and token label are per-card (e.g. label `GemP15-1`).

## Application AID

- IAS application AID (SELECT this first, as the file system is only reachable afterwards):
  `A0 00 00 00 18 40 00 00 01 63 42 00`
- The PKCS#15 application DF name (from EF.DIR) is `E8 28 BD 08 0F 01 "Gem P15"` at path `3F00/5000`.
  `E8 28 BD 08 0F` is **not** a selectable AID (SELECT returns `6A82`). It appears only as the DF name.

## Identity data files

The government identity/biometric objects (public, no PIN), distinct from the PKCS#15 `5000` DF used
for signing:

| File ID | Content | Format |
|---|---|---|
| `7001` | Document number | TLV, tag `5F01` |
| `7002` | Biographical data | TLV (1F-prefixed fields) |
| `7004` | Photo | JPEG, TLV with 2-byte length |
| `700B` | MRZ | TLV |
| `B001` | Signing certificate (X.509) | Binary (DER) |

Data fields are ASCII-encoded, except the expedition/issuance date. `B001` is the same holder
certificate referenced at `3F00/5000/B001` in the PKCS#15 layout. FirmaUY reads the biographical
data via `fetch-identity`/`fetch-photo` and the signing certificate via
`card_reader.read_file(conn, 0xB001)`.

TLV length encoding: `len < 0x80` single byte, `0x80..0xFF` → `81 XX`, `≤ 0xFFFF` → `82 XX XX`.

## PKCS#15 file layout

```
MF 3F00
├─ EF 0001            token serial
├─ EF.DIR 2F00        -> app "Gem P15" (E8 28 BD 08 0F 01 ...), path 3F00/5000
└─ DF 5000  (PKCS#15 application "Gem P15")
   ├─ EF 5031         EF(TokenInfo)
   ├─ EF 5032         EF(ODF)
   ├─ EF 5006         EF(AODF)  — "User PIN" (ref 0x11), "SO PIN"
   ├─ EF 5001         EF(CDF)   — certificate directory
   ├─ EF 5002         EF(PrKDF) — RSA private key, PIN-protected, key ref 0x01
   ├─ EF 5003         EF(PuKDF) — public key
   └─ B001            X.509 signing cert (RSA-2048)
```

Signing key = RSA-2048, protected by **User PIN ref `0x11`**, key reference `0x01`. In practice the
key signs via the PSO/DST path using the global key ref `0x01` directly (no explicit navigation into
DF `5000` is required before `MSE:SET DST`).

## PIN

| Property | Value |
|---|---|
| User PIN reference | `0x11` |
| Length | min 4 / max 8, stored padded to 12 with `0x00` |
| VERIFY APDU | `00 20 00 11 0C <PIN ASCII, 0x00-padded to 12>` (plain, no Secure Messaging) |
| Status probe | `00 20 00 11` (no body): `90 00` verified, `63 Cx` = x tries left, `69 83` blocked |

⚠️ A wrong **VERIFY** consumes PIN retries and can lock the card. FirmaUY probes the counter first
and refuses to spend the last try (see `native_card.verify_pin`). Failed **sign** (PSO) attempts do
not consume PIN retries once logged in.

The security status also persists across *successful* signatures. One VERIFY authorizes any number
of PSO:CDS operations in the same session (confirmed empirically with multi-file batch signing on a
real card), i.e. the signing key is **not** marked PIN-per-signature / user-consent.

## Signing flow (APDUs)

For `SHA256-RSA-PKCS` (algorithm reference `0x42` = RSA-PKCS#1 v1.5 | SHA-256, key ref `0x01`). This
is the standard IAS-ECC sequence, matching AGESIC's official description ("hash externally, then
load the hash"):

```
1. SELECT IAS app   00 A4 04 00 0C  A0 00 00 00 18 40 00 00 01 63 42 00
2. VERIFY PIN       00 20 00 11 0C  <PIN + 0x00 pad to 12>
3. MSE:SET DST      00 22 41 B6 06  80 01 42 84 01 01
4. PSO:HASH         00 2A 90 A0 22  90 20 <32-byte SHA-256 digest>
5. PSO:CDS          00 2A 9E 9A 00           -> 256-byte RSA-2048 signature (61 xx -> GET RESPONSE)
```

- **The message is hashed off-card.** PSO:HASH carries the final SHA-256 digest under tag `0x90`
  (`90 20 <digest>`). The card then builds the PKCS#1 DigestInfo and signs it in PSO:CDS.
- **MSE:SET DST** = `00 22 41 B6 06 80 01 42 84 01 01`: algorithm `0x42`, key reference `0x01`.
  There is no separate MSE:SET HT.
- **PSO:HASH** answers `61 20` (32 bytes of on-card digest available). The command is Case 3 (no
  `Le`), so no GET RESPONSE is issued and the echoed digest is discarded. **`61 20` is success**,
  not an error.
- **PSO:CDS** = `00 2A 9E 9A 00` returns the RSA-2048 signature (256 bytes via `61 xx` → GET
  RESPONSE `00 C0 00 00 xx`).
- Only **SHA-256** (`0x42`) is exercised in practice. The card declares SHA-224/384/512 too
  (`0x32/0x52/0x62`).

## Quirks (the things that bite you)

1. **Strict SELECT P1/P2.** The card enforces strict ISO 7816-4 SELECT P1 semantics and rejects the
   "path from current DF" shortcut (`P1=0x09`) with `6A86`. Use the exact P1 per selection type
   (MF/DF `00`, EF-under-DF `02`, path-from-MF `08`, AID `04`).

2. **SDO GET DATA not supported.** `00 CB 3F FF … 4D …` returns `6A86`. PIN/key metadata must come
   from the PKCS#15 structures. (Odd-INS access-rule reads like `00 CB 00 FF 05 7B 03 80 01 0x` *are*
   supported.)

3. **PSO:HASH takes a pre-computed digest, not an intermediate-hash DO.** The card accepts the simple
   `90 <len> <digest>` form (a finished SHA-256 digest) and signs it. It does **not** need, and in
   practice **rejects with `6A80`**, the intermediate-hash data object
   `90 28 <state(32)><counter(8)> 80 <len> <data>` where the card would finalize the hash itself.
   Hash in software and hand the card the digest.

4. **No INTERNAL AUTHENTICATE for the signing key.** `00 88 00 00 <DigestInfo>` returns `67 00`. This
   key signs via the PSO/DST path, not INTERNAL AUTHENTICATE.

## Cryptographic algorithms (declared by AGESIC)

- Primary **RSA-2048**. ECDSA also declared. Hashes SHA-224/256/384/512.
- RSA padding: ISO 9796-2, PKCS#1 v1.5, RFC 2409, PSS variants.
- `AlgoID = 0x42` → RSA + SHA-256 + PKCS#1 v1.5.

## Biometrics: Match On Card (not used by FirmaUY)

- ISO/IEC 19794-2 Compact Card fingerprint minutiae, 3 bytes/minutia, max 192 bytes (64 minutiae),
  ordered by ascending Y then X. `MATCH ON CARD` = `INS 21h` (`P2=4Ah` new eID, `21h` legacy). The
  card blocks after 5 consecutive failed Match-on-Card attempts.

## NFC / contactless (2022 v5 eID)

- **PACE** (Password Authenticated Connection Establishment). References: BSI TR-03110 Part 2, BSI
  TR-03111, ICAO Doc 9303 Part 11. FirmaUY uses the contact interface only.

## Core APDU commands

| Operation | INS | Purpose |
|---|---|---|
| SELECT (app / file) | `A4` | Select applet or file by ID |
| READ BINARY | `B0` | Read file data (short-offset, P1 carries the high offset byte) |
| VERIFY PIN / IS VERIFIED | `20` | Authenticate / check PIN status |
| MATCH ON CARD | `21` | Biometric validation |
| MSE:SET DST | `22` | Set signature algorithm / key |
| PSO:HASH / PSO:CDS | `2A` | Load the digest / compute the signature |

## Standards referenced

ISO/IEC 7816 (smart card interface), ISO/IEC 19794-2 (fingerprint minutiae), ISO/IEC 9796-2 & PKCS#1
v1.5 (RSA padding), RFC 2409, BSI TR-03110 / TR-03111 and ICAO Doc 9303 Part 11 (contactless / PACE).
