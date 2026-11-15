# Guía de uso

Esta guía recorre todos los comandos de `firmauy`, sus opciones frecuentes y las salidas que
producen. Para una instalación desde cero, empezá por [Instalación y configuración](instalacion.md).
Para recetas concretas, mirá el [Recetario](recetario.md).

> **¿Primera vez?** Ejecutá `firmauy doctor` antes de firmar. Revisa el módulo PKCS#11, el servicio
> PC/SC, la tarjeta y las anclas de confianza, y no necesita PIN.

## Ayuda y versión

```bash
firmauy --version
firmauy --help
firmauy sign-pdf --help
```

Cada comando tiene su propia ayuda con todas las opciones y los valores predeterminados.

## Firmar un archivo con detección automática

`firmauy sign` elige el tipo de firma según el contenido:

- PDF: PAdES embebida.
- XML: XAdES envuelta.
- Cualquier otro archivo: CAdES separada, con extensión `.p7s`.

```bash
firmauy sign documento.pdf              # produce documento_firmado.pdf
firmauy sign datos.xml                  # produce datos_firmado.xml
firmauy sign contrato.docx              # produce contrato.docx.p7s
firmauy sign documento.pdf --as cades   # fuerza una firma CAdES separada
```

Las opciones de apariencia del PDF (posición, imagen, texto) solo se aplican cuando la salida es
PDF.

## Firmar un PDF

```bash
firmauy sign-pdf entrada.pdf
firmauy sign-pdf entrada.pdf salida.pdf
firmauy sign-pdf entrada.pdf salida.pdf --overwrite
```

Sin ruta de salida, el nombre es `<entrada>_firmado.pdf`. La firma es visible por defecto.

### Elegir la página y la posición

```bash
# Última página, el valor predeterminado
firmauy sign-pdf entrada.pdf --page -1

# Página 1, con un rectángulo explícito en puntos
firmauy sign-pdf entrada.pdf --page 1 --x1 50 --y1 50 --x2 300 --y2 140

# Una esquina, con margen desde los bordes
firmauy sign-pdf entrada.pdf --corner bottom-right --margin 24
```

Los valores de `--corner` son `bottom-left`, `bottom-right`, `top-left` y `top-right`. Si usás
`--corner`, no hace falta indicar `--x1`, `--y1`, `--x2` ni `--y2`.

### Texto de la firma

La apariencia incluye título, firmante, documento, fecha y emisor. Podés quitar cada bloque:

```bash
firmauy sign-pdf entrada.pdf \
  --no-stamp-title \
  --no-stamp-document \
  --no-stamp-issuer
```

### Imagen

```bash
firmauy sign-pdf entrada.pdf --image firma.png
firmauy sign-pdf entrada.pdf --image firma.png --image-mode side
firmauy sign-pdf entrada.pdf --image firma.png --image-mode only
firmauy sign-pdf entrada.pdf --image fondo.png --image-mode background --image-opacity 0.15
```

Los modos son:

- `background`: la imagen va detrás del texto.
- `side`: la imagen va al costado del texto.
- `only`: solo la imagen, sin texto.

La imagen se valida antes de pedir el PIN. Un archivo inválido no consume un intento.

### Metadatos de la firma

```bash
firmauy sign-pdf entrada.pdf \
  --reason "Aprobación de contrato" \
  --location "Montevideo" \
  --contact-info "persona@ejemplo.uy" \
  --field-name FirmaContrato
```

La zona horaria de la fecha visible se puede cambiar con `--timezone`, por ejemplo
`--timezone America/Montevideo`.

### PDF con referencias cruzadas híbridas

Por seguridad, esos PDF se rechazan de forma predeterminada, porque la firma incremental puede no
ser equivalente para todos los lectores. Normalizá el archivo con `qpdf`:

```bash
qpdf in.pdf normalizado.pdf
firmauy sign-pdf normalizado.pdf
```

La opción `--allow-hybrid-xref` existe, pero abre el PDF en modo no estricto y queda bajo tu
responsabilidad.

## Firmar XML

```bash
firmauy sign-xml documento.xml
firmauy sign-xml documento.xml firmado.xml
firmauy sign-xml documento.xml --tsa-url https://tsa.ejemplo.uy
```

La firma es XAdES-BES, o XAdES-T cuando se indica una TSA. El documento original no se modifica si
elegís una ruta de salida distinta.

## Firmar cualquier archivo

```bash
firmauy sign-any contrato.zip
firmauy sign-any contrato.zip contrato.zip.p7s
firmauy verify-any contrato.zip.p7s --original contrato.zip
```

La salida es una firma CAdES separada. El archivo original queda intacto. Para verificar hace falta
el original, ya sea por la convención de nombres o con `--original`.

## Firmar por lote

Los comandos por lote abren una sola sesión con la tarjeta y firman varios archivos. Esto reduce los
contactos con el lector y evita pedir el PIN una vez por archivo.

```bash
# Varios PDF por argumentos
firmauy sign-pdf-batch a.pdf b.pdf --output-dir firmados

# Una carpeta completa
firmauy sign-pdf-batch --input-dir documentos --output-dir firmados

# XML
firmauy sign-xml-batch --input-dir xml --output-dir xml-firmados

# Archivos arbitrarios
firmauy sign-any-batch --input-dir adjuntos --output-dir adjuntos-firmados

# Tipos mezclados
firmauy sign-batch --input-dir entrada --output-dir salida
```

La opción `--suffix` cambia el sufijo de salida. El valor predeterminado es `_firmado`.

Los archivos de entrada por lote quedan confinados al directorio indicado. Una ruta que intente
salir de él, incluso mediante un enlace simbólico, se omite y se informa.

## Opciones comunes de firma

### PIN

```bash
firmauy sign-pdf documento.pdf
firmauy sign-pdf documento.pdf --pin-source fd --pin-fd 3 3< pin.txt
printf '%s\n' "$PIN" | firmauy sign-pdf documento.pdf --pin-source stdin
firmauy sign-pdf documento.pdf --pin-source env --pin-env-var FIRMAUY_PIN
```

No hay opción `--pin`. El PIN nunca debe ir como argumento.

### Backend nativo

```bash
firmauy sign-pdf documento.pdf --native
firmauy sign-pdf documento.pdf --native --reader "ACS ACR39U 00 00"
firmauy doctor --native
```

El modo nativo no usa PKCS#11. `--pkcs11-lib` y `--token-label` se ignoran con `--native`, y
`--cert-id` se rechaza.

### Certificado y token

```bash
firmauy list-tokens
firmauy list-certs
firmauy sign-pdf documento.pdf --token-label "Cédula de Identidad"
firmauy sign-pdf documento.pdf --cert-id 0123456789abcdef
```

### Sobrescritura y validación posterior

```bash
firmauy sign-pdf documento.pdf --overwrite
firmauy sign-pdf documento.pdf --verify
firmauy sign-pdf documento.pdf --dry-run
```

`--verify` verifica la firma recién creada antes de terminar. `--dry-run` valida opciones y
archivos, y se detiene antes de la tarjeta: no pide PIN ni firma.

### Silencio en registros

```bash
firmauy sign-pdf documento.pdf --quiet
```

`--quiet` oculta el bloque con nombre del firmante, emisor, serie del certificado e ID PKCS#11. La
firma y la verificación siguen funcionando.

## Verificar

```bash
firmauy verify documento_firmado.pdf
firmauy verify documento_firmado.xml
firmauy verify documento.p7s --original documento.pdf
firmauy verify-pdf documento_firmado.pdf
firmauy verify-xml documento_firmado.xml
firmauy verify-any documento.p7s --original documento.pdf
```

La verificación es local y sin tarjeta. Incluye la integridad de la firma y, salvo que uses
`--no-trust`, la cadena de certificados hasta la raíz nacional.

Los códigos de salida son:

| Código | Significado |
|---|---|
| `0` | VALID: integridad correcta y cadena confiable |
| `1` | INVALID: integridad rota, o cadena no confiable o revocada |
| `2` | INDETERMINATE: integridad correcta, pero no se pudo establecer la confianza |

### Opciones de verificación

```bash
# Solo integridad, sin evaluar la cadena
firmauy verify documento_firmado.pdf --no-trust

# Anclas propias
firmauy verify documento_firmado.pdf --ca-file mis-anclas.pem

# Revocación en línea
firmauy verify documento_firmado.pdf --check-revocation

# Anclas de la TSA, para validar el sellado de tiempo
firmauy verify documento_firmado.pdf --tsa-ca tsa.pem

# Permitir una TSA o un espejo de revocación en la red interna
firmauy verify documento_firmado.pdf --check-revocation --allow-private-network
```

`--no-trust` usa una lista de anclas vacía de forma explícita. Nunca cae al almacén de confianza del
sistema operativo.

`--check-revocation` necesita red. Los pedidos van solo a direcciones públicas, con límites de
tamaño, tiempo y redirecciones. `--allow-private-network` habilita loopback y redes privadas para
una TSA o un espejo interno; las direcciones link-local, donde responden los metadatos de la nube,
siguen rechazadas.

Sin `--tsa-ca`, un sellado de tiempo se informa como presente pero no validado. No se considera
confiable ni roto.

## Leer la tarjeta sin PIN

### Identidad

```bash
firmauy fetch-identity
firmauy fetch-identity --json
firmauy fetch-identity --json-pretty
firmauy fetch-identity --redact
firmauy fetch-identity --json --redact
```

La salida humana muestra los campos en una tabla. `--redact` reemplaza todos los datos personales
por `[REDACTED]`. Los datos de identidad son personales aunque la tarjeta los entregue sin PIN.

### Foto

```bash
firmauy fetch-photo                         # cedula_foto.jpg
firmauy fetch-photo foto.jpg                # ruta explícita
firmauy fetch-photo --overwrite             # reemplaza una foto existente
firmauy fetch-photo - > foto.jpg            # JPEG crudo por stdout
firmauy fetch-photo - | feh -               # sin archivo en disco
firmauy fetch-photo --json                  # metadatos y base64
firmauy fetch-photo --json --redact         # sin imagen ni huellas
```

Escribir bytes binarios en una terminal interactiva se rechaza. Redirigí o usá una tubería.

El registro `--json` incluye formato, MIME, ancho, alto, cantidad de bytes, SHA-256 y la imagen en
base64. `--redact` elimina la imagen, el hash y el conteo de bytes, porque permiten identificar o
correlacionar a la persona. Sin `--json`, `--redact` se rechaza: una foto redactada no tendría nada
que escribir.

### Lectores

```bash
firmauy list-readers
firmauy list-readers --json
firmauy fetch-identity --reader "Alcor Link AK9563 00 00"
```

Si hay exactamente un lector, se detecta solo. Si hay varios, hay que indicar `--reader`.

### Diagnóstico

```bash
firmauy doctor
firmauy doctor --native
firmauy doctor --json
firmauy doctor --json-pretty
```

`doctor` no necesita PIN. Devuelve estado 0 si no hay FAIL y 1 si hay al menos uno.

### Validar una cédula

```bash
firmauy validate-ci 1.234.567-8
firmauy validate-ci 12345678 --json
firmauy validate-ci 1234567 --complete
```

No necesita tarjeta ni PIN. Valida el dígito verificador o lo completa.

### Actualizar las anclas nacionales

```bash
firmauy fetch-cas
firmauy fetch-cas --from-file mica.pem
```

Es opcional: las anclas ya vienen incluidas. `fetch-cas` actualiza una caché por usuario. Las
copias se aceptan solo si coinciden con la huella SHA-256 fijada.

## Salida JSON

Los comandos de firma, verificación, tarjeta y diagnóstico aceptan `--json`. stdout lleva un único
objeto JSON y nada más; los avisos van a stderr y el código de salida no cambia.

Ejemplo de firma:

```json
{"schema_version": 2, "ok": true, "kind": "pades", "output": "doc_firmado.pdf", "verified": false}
```

Ejemplo de error:

```json
{"schema_version": 2, "ok": false, "error_code": "incorrect_pin", "error": "Incorrect PIN."}
```

`error_code` es estable y permite ramificar sin leer el texto. Algunos valores:
`incorrect_pin`, `pin_locked`, `pin_error`, `reader_not_found`, `card_not_found`,
`certificate_not_found`, `certificate_not_valid`, `output_exists`, `file_not_found`,
`timestamp_destination_refused`, `timestamp_failed`, `invalid_argument` y `operation_failed`.

En verificación, el código de salida sigue siendo 0, 1 o 2 y el objeto JSON describe el resultado.
Con `--redact` se ocultan nombre del firmante, número de documento y series.

## Límites y comportamiento seguro

- XML: hasta 16 MiB. Se deshabilitan entidades externas, red y árboles gigantes.
- PDF en verificación: hasta 128 MiB.
- Firma CMS separada: hasta 8 MiB.
- Respuesta de una TSA: hasta 4 MiB.
- Los archivos existentes no se sobrescriben sin `--overwrite`.
- La salida se escribe de forma atómica y no se sigue un enlace simbólico en la ruta de salida.
- No ejecutes dos operaciones con la misma tarjeta al mismo tiempo: las sesiones PC/SC chocan.

Para el detalle de cada control, leé [Seguridad y claves](seguridad.md).

