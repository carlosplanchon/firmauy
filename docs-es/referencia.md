# Referencia

Datos técnicos para integradores: API de Python, códigos de salida, contrato JSON, variables de
entorno y enlaces a la documentación profunda en inglés.

## API de Python

El paquete expone `firmauy.api` con objetos de resultado inmutables y errores tipados. No imprime
nada, no llama a `sys.exit` y no depende de la CLI.

```python
from firmauy.api import (
    sign, sign_pdf, sign_xml, sign_file, sign_files,
    verify, run_doctor,
    validate_ci, complete_ci,
    fetch_identity, fetch_photo,
    list_readers, list_tokens, list_certs,
    fetch_cas,
)
```

### Firmar

```python
import getpass
from firmauy.api import sign, sign_pdf

reporte = sign("contrato.pdf", pin_provider=lambda: getpass.getpass("PIN: "))
print(reporte.kind)          # "pades"
print(reporte.output_path)   # ruta del archivo firmado

reporte = sign_pdf(
    "contrato.pdf",
    output="firmados/contrato.pdf",
    pin_provider=lambda: getpass.getpass("PIN: "),
    page=1,
    corner="bottom-right",
)
```

`sign` detecta el formato. `sign_pdf`, `sign_xml` y `sign_file` fuerzan el tipo. `sign_files` firma
un lote con una sola sesión.

La opción `pin` existe en la API, pero para uso interactivo se recomienda `pin_provider`, que se
invoca recién después de las verificaciones que no necesitan PIN.

### Verificar

```python
from firmauy.api import verify

resultado = verify("contrato_firmado.pdf")
print(resultado.indication)   # "VALID", "INVALID" o "INDETERMINATE"
```

Opciones principales:

- `original=`: archivo original para una firma CAdES separada.
- `ca_file=`: anclas de confianza propias.
- `trust=False`: omite la evaluación de la cadena.
- `check_revocation=True`: consulta CRL u OCSP.
- `allow_private_network=True`: permite destinos internos.
- `tsa_ca_file=`: anclas de la TSA.

### Tarjeta y diagnóstico

```python
from firmauy.api import fetch_identity, fetch_photo, list_readers, run_doctor

for lector in list_readers():
    print(lector)

identidad = fetch_identity()
print(identidad.lastnames, identidad.document_number)

foto = fetch_photo()
print(foto.width, foto.height, foto.sha256)

diagnostico = run_doctor()
print(diagnostico.ok)
```

`fetch_identity` y `fetch_photo` no necesitan PIN. Los objetos de resultado contienen los mismos
datos que la salida JSON, sin redacción por defecto. Si vas a registrar o compartir esos datos,
usá la CLI con `--redact` o descartá los campos personales en tu código.

### Cédula y anclas

```python
from firmauy.api import validate_ci, complete_ci, fetch_cas

print(validate_ci("1.234.567-8").valid)
print(complete_ci("1234567"))
fetch_cas()
```

`validate_ci` y `complete_ci` no necesitan tarjeta. `fetch_cas` actualiza la caché de anclas
nacionales y verifica las huellas fijadas.

## Códigos de salida

| Comando | 0 | 1 | 2 |
|---|---|---|---|
| `verify`, `verify-pdf`, `verify-xml`, `verify-any` | VALID | INVALID | INDETERMINATE |
| `sign-*`, `fetch-*`, `doctor`, `list-*`, `fetch-cas` | Éxito | Error | No se usa |
| `doctor` | Sin FAIL | Al menos un FAIL | No se usa |
| `list-readers` | Hay lectores | No hay lectores | No se usa |

En los comandos de firma, un error de validación, de tarjeta o de red termina con 1.

## Contrato JSON

Con `--json` o `--json-pretty`, stdout contiene un único objeto. Los avisos van a stderr.

Campos comunes:

```json
{"schema_version": 2, "ok": true}
```

Error:

```json
{"schema_version": 2, "ok": false, "error_code": "incorrect_pin", "error": "Incorrect PIN."}
```

Firma:

```json
{"schema_version": 2, "ok": true, "kind": "pades", "output": "doc_firmado.pdf", "verified": false}
```

Lote:

```json
{"schema_version": 2, "ok": false, "signed": 2, "total": 3, "errors": 1, "warnings": 0,
 "files": [{"input": "a.pdf", "output": "f/a_firmado.pdf", "status": "ok", "kind": "pades"}]}
```

Códigos de error estables:

| Código | Significado |
|---|---|
| `incorrect_pin` | PIN incorrecto |
| `pin_locked` | PIN bloqueado |
| `pin_error` | PIN rechazado antes de la tarjeta |
| `reader_not_found` | No hay lector PC/SC |
| `card_not_found` | Hay lector pero no responde una tarjeta |
| `token_not_found` | No hay token PKCS#11 |
| `certificate_not_found` | No hay certificado que coincida |
| `certificate_not_valid` | Certificado fuera de vigencia |
| `signing_key_not_found` | Certificado sin clave privada |
| `output_exists` | La salida existe sin `--overwrite` |
| `output_committed` | La salida se escribió pero falló un paso posterior |
| `output_access_control` | No se pudieron conservar los permisos |
| `post_sign_verification_failed` | `--verify` falló después de firmar |
| `detached_original_required` | Falta el original de una firma `.p7s` |
| `timestamp_destination_refused` | La política de red rechazó la TSA |
| `timestamp_failed` | Falló el sellado de tiempo |
| `file_not_found` | Falta un archivo |
| `invalid_argument` | Argumento inválido |
| `operation_failed` | Error no clasificado |

## Variables de entorno

| Variable | Efecto |
|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Se respetan en los pedidos salientes opcionales |
| `XDG_CACHE_HOME` | Ubicación de la caché de anclas nacionales en Linux |
| `LOCALAPPDATA` | Ubicación de la caché en Windows |
| `FIRMAUY_PIN` | Ejemplo de variable para `--pin-source env`; FirmaUY no la define |

`~/.netrc` no se lee nunca.

## Límites

| Dato | Límite |
|---|---|
| XML | 16 MiB |
| PDF en verificación | 128 MiB |
| CMS `.p7s` en verificación | 8 MiB |
| Respuesta de TSA | 4 MiB |
| Redirecciones de revocación | 3 |
| Tiempo total por pedido | 30 s para TSA y OCSP, 300 s para CRL |

## Enlaces técnicos

- [Seguridad y claves](seguridad.md): modelo de seguridad completo.
- [Protocolo de la tarjeta](https://carlosplanchon.github.io/firmauy/en/card-protocol/): APDUs del
  backend nativo.
- [Anclas de confianza](https://carlosplanchon.github.io/firmauy/en/trust-anchors/): certificados,
  huellas y revocación.
- [API completa](https://carlosplanchon.github.io/firmauy/en/api/): referencia detallada de cada
  función y cada objeto.
- [Invariantes de seguridad](https://carlosplanchon.github.io/firmauy/en/security-invariants/):
  evidencia de las pruebas de sellado de tiempo.
- [Backend OpenSC](https://carlosplanchon.github.io/firmauy/en/opensc-backend/): compilación y uso.

