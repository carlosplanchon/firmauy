#!/usr/bin/env bash
#
# Dev-only PKCS#11 token (SoftHSM2) that mimics a cédula closely enough to
# exercise the full `firmauy` signing pipeline WITHOUT using the real card.
#
# Why: putting the real cédula PIN in wrong too many times BLOCKS the card.
# SoftHSM has no such lockout, so develop and test against it freely.
#
# What it produces: a structurally valid, cryptographically sound signed PDF.
# It will NOT validate as a *cédula* signature on https://firma.gub.uy/
# (the issuing CA here is fake, by design). Use the real card only for a final,
# deliberate validation run once everything else works.
#
# Requirements (Arch): sudo pacman -S softhsm opensc openssl
#
# Usage:
#   bash scripts/dev-softhsm-setup.sh
# then follow the printed commands (run them in the SAME shell, or re-export
# SOFTHSM2_CONF as shown).
set -euo pipefail

# --- Local, root-free SoftHSM store (everything stays under ./.softhsm) -------
WORK="$(pwd)/.softhsm"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
TOKENDIR="$WORK/tokens"
mkdir -p "$TOKENDIR"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKENDIR
objectstore.backend = file
log.level = ERROR
EOF

# Pick the first SoftHSM module we can find (path varies by distro).
MODULE=""
for cand in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/pkcs11/libsofthsm2.so \
    /usr/lib/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so; do
    if [ -e "$cand" ]; then MODULE="$cand"; break; fi
done
: "${MODULE:?libsofthsm2.so not found — install softhsm first}"

PIN=1234
SOPIN=0000
LABEL=test-cedula
ID=01

# --- Init a fresh token -------------------------------------------------------
rm -rf "${TOKENDIR:?}/"*
softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SOPIN" --pin "$PIN"

# --- Build a fake "Ministerio del Interior" CA + a leaf identity cert ---------
# The leaf subject carries serialNumber + CN and the issuer is the fake MI CA,
# so firmauy's certificate-scoring heuristic picks it on the real PKCS#11 path.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/ca.key"
openssl req -x509 -new -key "$TMP/ca.key" -days 3650 -out "$TMP/ca.crt" \
  -subj "/C=UY/CN=Autoridad Certificadora del Ministerio del Interior"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/leaf.key"
openssl req -new -key "$TMP/leaf.key" -out "$TMP/leaf.csr" \
  -subj "/C=UY/CN=PEREZ PEREZ JUAN/serialNumber=1.2.3.4-12345678"

cat > "$TMP/leaf.ext" <<EOF
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, clientAuth
EOF

openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" \
  -CAcreateserial -days 825 -extfile "$TMP/leaf.ext" -out "$TMP/leaf.crt"
openssl x509 -in "$TMP/leaf.crt" -outform DER -out "$TMP/leaf.der"

# --- Import key + cert with matching CKA_ID so has_private_key() pairs them ---
softhsm2-util --import "$TMP/leaf.key" --token "$LABEL" --label leaf --id "$ID" --pin "$PIN"
pkcs11-tool --module "$MODULE" --token-label "$LABEL" --login --pin "$PIN" \
  --write-object "$TMP/leaf.der" --type cert --id "$ID" --label leaf

cat <<EOF

Done. Fake cédula token ready.

  Module      : $MODULE
  Token label : $LABEL
  PIN         : $PIN

SoftHSM exposes the initialised token plus a free slot, so firmauy sees more
than one token; always pass --token-label $LABEL.

Run (in THIS shell, or re-export SOFTHSM2_CONF=$SOFTHSM2_CONF first):

  uv run firmauy list-certs --pkcs11-lib $MODULE --token-label $LABEL --pin-source stdin <<< $PIN
  uv run firmauy sign input.pdf out.pdf --pkcs11-lib $MODULE --token-label $LABEL --pin-source stdin <<< $PIN

Reset everything with:  rm -rf $WORK
EOF
