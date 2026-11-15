# Recetario

Recetas cortas para tareas frecuentes. Todas usan la CLI `firmauy`; los ejemplos con `jq` necesitan
que esté instalado.

## Firmar un documento y verificarlo antes de enviarlo

```bash
firmauy sign-pdf contrato.pdf contratos/contrato_firmado.pdf
firmauy verify contratos/contrato_firmado.pdf
```

Si la verificación devuelve 0, el archivo es técnicamente válido y la cadena llega a la raíz
nacional. Después hacé el control oficial en <https://firma.gub.uy/>.

## Firmar sin dejar el PIN en el historial

Usá un descriptor de archivo heredado:

```bash
read -r -s -p "PIN: " PIN; printf '%s\n' "$PIN" > pin.txt
firmauy sign-pdf contrato.pdf --pin-source fd --pin-fd 3 3< pin.txt
shred -u pin.txt
unset PIN
```

El PIN no aparece en `argv`, en el entorno del proceso ni en el historial. El archivo temporal se
borra al terminar.

## Automatizar con JSON

```bash
firmauy sign-pdf contrato.pdf --json > resultado.json
jq -e '.ok and .kind == "pades"' resultado.json
```

Para firma por lote, el objeto incluye `files` con el estado de cada entrada:

```bash
firmauy sign-batch --input-dir entrada --output-dir salida --json > lote.json
jq -r '.files[] | select(.status != "ok") | .input' lote.json
```

## Firmar una carpeta mixta en una sola sesión

```bash
firmauy sign-batch --input-dir documentos --output-dir firmados
```

El comando firma PDF como PAdES, XML como XAdES y el resto como CAdES separada. Abre una sola sesión
con la tarjeta, así que el PIN se pide una vez.

## Firmar un PDF con una imagen y una esquina

```bash
firmauy sign-pdf contrato.pdf \
  --image firma.png \
  --image-mode side \
  --corner bottom-right \
  --margin 18
```

## Preparar un PDF que no es compatible

Si el PDF usa referencias cruzadas híbridas, normalizalo primero:

```bash
qpdf original.pdf normalizado.pdf
firmauy sign-pdf normalizado.pdf
```

## Leer la identidad y compartirla sin datos personales

```bash
firmauy fetch-identity --json --redact
```

La salida conserva la estructura y los valores booleanos no identificatorios, pero reemplaza todos
los campos personales por `[REDACTED]`. No compartas una salida sin `--redact`: incluye nombre,
fecha y lugar de nacimiento, número de documento y MRZ.

## Exportar la foto sin escribirla en disco

```bash
firmauy fetch-photo - > foto.jpg
firmauy fetch-photo - | feh -
```

Para un registro con metadatos:

```bash
firmauy fetch-photo --json > foto.json
jq -r '.sha256, .width, .height' foto.json
firmauy fetch-photo --json --redact > foto_redactada.json
```

## Validar una cédula sin tarjeta

```bash
firmauy validate-ci 1.234.567-8
firmauy validate-ci 1234567 --complete
```

Sirve para controles de formularios o para verificar un número antes de usarlo.

## Verificar sin confiar en el sistema operativo

```bash
firmauy verify documento_firmado.pdf --no-trust
```

Este modo solo comprueba integridad. No evalúa la cadena y no reporta al firmante como confiable.
Usalo para diagnosticar, no como aprobación final.

## Verificar contra anclas propias

```bash
firmauy verify documento_firmado.pdf --ca-file anclas-internas.pem
```

Las anclas propias no están fijadas por FirmaUY. Sos responsable de su origen y vigencia.

## Firmar con sellado de tiempo

```bash
firmauy sign-pdf contrato.pdf --tsa-url https://tsa.ejemplo.uy
firmauy verify contrato_firmado.pdf --tsa-ca tsa.pem
```

Sin `--tsa-ca`, el sello se informa como presente pero no validado. El sellado es opcional y no
forma parte del flujo estándar de la cédula.

## Verificar revocación

```bash
firmauy verify documento_firmado.pdf --check-revocation
```

Necesita red y un respondedor CRL u OCSP alcanzable. Si la consulta falla o el destino se rechaza,
la cadena lo informa; no se convierte en un VALID silencioso.

## Usar un lector específico

```bash
firmauy list-readers
firmauy sign-pdf contrato.pdf --native --reader "ACS ACR39U 00 00"
firmauy fetch-identity --reader "ACS ACR39U 00 00"
```

## Trabajar con varias tarjetas o lectores

No ejecutes dos comandos sobre la misma tarjeta en paralelo: PC/SC comparte el lector y las sesiones
chocan. Terminá un comando antes de iniciar el siguiente. Si hay varios lectores conectados,
indicá `--reader` en todos los comandos.

## Diagnosticar un fallo

```bash
firmauy doctor
firmauy doctor --native
firmauy doctor --json | jq '.checks[] | select(.status != "PASS")'
```

`doctor` no pide PIN, así que es seguro ejecutarlo antes de intentar firmar.

## Registrar una firma en CI sin datos personales

```bash
firmauy sign-pdf contrato.pdf --quiet --json
```

`--quiet` omite el bloque del firmante. El JSON sigue teniendo el resultado y la ruta de salida.

