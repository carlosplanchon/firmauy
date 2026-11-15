# FirmaUY

**Tu cédula es una clave de firma. FirmaUY la lleva a la terminal.**

FirmaUY firma y verifica PDF, XML y cualquier archivo con la cédula de identidad uruguaya, a través
de PKCS#11 o, de forma opcional, de PC/SC. Genera firmas con estándares abiertos (PAdES, XAdES y
CAdES) y valida toda la cadena de confianza de forma local contra la raíz nacional uruguaya. Los
documentos no salen de tu equipo.

Podés usarlo desde la terminal o desde Python a través de su API pública.

!!! warning "No oficial y experimental"
    FirmaUY realiza firma y verificación técnicas y locales. No está afiliado a AGESIC, no está
    certificado oficialmente y no garantiza validez legal. Para trámites legales o administrativos,
    usá el validador oficial en <https://firma.gub.uy/>.

!!! tip "Siempre contrastá lo que firmás"
    Antes de enviar o aceptar un documento firmado, subilo a <https://firma.gub.uy/> y guardá la
    respuesta. Que FirmaUY valide su propia salida no es evidencia independiente. Subir el documento
    lo envía a un servicio del Estado, así que tratá el material confidencial según corresponda. Un
    archivo `.p7s` separado no se puede validar en ese portal.

## Inicio rápido

Requisitos: Linux o Windows (x64), un lector de tarjetas inteligentes y el middleware PKCS#11 de la
cédula o el backend nativo por PC/SC.

```bash
uv tool install firmauy          # instala la CLI en un entorno aislado
firmauy doctor                   # revisa el lector, el módulo y la tarjeta
firmauy list-tokens              # confirma que la tarjeta se detecta
firmauy sign-pdf entrada.pdf     # firma; pide el PIN sin mostrarlo
firmauy verify entrada_firmado.pdf  # verifica localmente, incluida la cadena
```

Después subí `entrada_firmado.pdf` a <https://firma.gub.uy/>.

¿Es tu primera vez? Empezá por [Instalación y configuración](instalacion.md) y seguí con la
[Guía de uso](uso.md).

## Qué hace

| Formato | Comando | Salida | Verificación | Sellado de tiempo |
|---|---|---|---|---|
| PDF / PAdES | `sign-pdf` | `.pdf` firmado | `verify-pdf` o `verify` | opcional, TSA externa |
| XML / XAdES | `sign-xml` | `.xml` firmado | `verify-xml` o `verify` | opcional, TSA externa |
| Cualquier archivo / CAdES | `sign-any` | `.p7s` separado | `verify-any` o `verify` | opcional, TSA externa |

Cada comando tiene una variante por lote (`sign-pdf-batch`, `sign-xml-batch`, `sign-any-batch`) y
existen los comandos mixtos `sign` y `sign-batch`. La firma PDF visible se parece a la de los
documentos firmados con la cédula.

La tarjeta también se puede leer sin PIN:

| Comando | Qué lee |
|---|---|
| `fetch-identity` | Nombres, fecha de nacimiento, lugar de nacimiento, número de documento y MRZ |
| `fetch-photo` | La foto JPEG de la persona titular |
| `list-readers` | Lectores PC/SC disponibles |
| `list-tokens` / `list-certs` | Tokens y certificados PKCS#11 |
| `validate-ci` | Validación del dígito verificador, sin tarjeta |
| `doctor` | Diagnóstico de la instalación |

## Dónde está la clave

La clave privada se genera cuando se emite la cédula, se guarda en el elemento seguro de la tarjeta
y nunca sale de ahí. FirmaUY no tiene operaciones para importar, exportar, respaldar ni recuperar
claves. Le pide a la tarjeta que firme y recibe una firma. El PIN habilita esa operación y nunca se
almacena.

Leé [Seguridad y claves](seguridad.md) para ver el modelo completo: protección del PIN y del
contador de intentos, anclas de confianza, escritura atómica de archivos, límites de entrada,
política de red saliente y qué queda fuera del alcance.

## Documentación

- [Instalación y configuración](instalacion.md): sistemas operativos, middleware, instalación,
  primera firma y solución de problemas.
- [Guía de uso](uso.md): todos los comandos, opciones y salidas.
- [Recetario](recetario.md): recetas de privacidad, automatización y tuberías.
- [Seguridad y claves](seguridad.md): cómo se aplica la seguridad y qué no cubre.
- [Referencia](referencia.md): API de Python, variables, códigos de salida y enlaces técnicos.

La documentación técnica de referencia está en inglés: [anclas de
confianza](https://carlosplanchon.github.io/firmauy/en/trust-anchors/), [protocolo de la
tarjeta](https://carlosplanchon.github.io/firmauy/en/card-protocol/), [API
completa](https://carlosplanchon.github.io/firmauy/en/api/) y [backend
OpenSC](https://carlosplanchon.github.io/firmauy/en/opensc-backend/).

## Uso como biblioteca

```python
import getpass
from firmauy.api import sign, verify

reporte = sign("contrato.pdf", pin_provider=lambda: getpass.getpass("PIN: "))
print(reporte.kind, "->", reporte.output_path)
print(verify(reporte.output_path).indication)
```

`pin_provider` se ejecuta recién después de que el lector, la tarjeta y el certificado pasan las
verificaciones, así que una instalación rota nunca consume un intento de PIN.

## Privacidad

FirmaUY funciona de forma local. La firma y la verificación no envían documentos a ningún lado. Las
opciones `--tsa-url` y `--check-revocation` hacen pedidos salientes solo a direcciones públicas, con
límites de tamaño, tiempo y redirecciones. La única subida recomendada es el control en
<https://firma.gub.uy/>, y es tu decisión.

Los datos de identidad y la foto son datos personales. Usá `--redact` antes de compartirlos y
`--quiet` en los comandos de firma dentro de registros automatizados para ocultar el bloque del
firmante.

