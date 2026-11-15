# Instalación y configuración

Esta guía te lleva desde un equipo sin preparar hasta un documento firmado y verificado localmente.
Ejecutá `firmauy doctor` cada vez que algo no funcione: revisa toda la cadena y no necesita PIN.

## Qué necesitás

### Hardware

- Un lector de tarjetas inteligentes compatible con PC/SC.
- Una cédula uruguaya con certificado de firma vigente.

### Sistema operativo

- **Linux:** el desarrollo y las pruebas principales se hacen en Arch Linux. Debian y Ubuntu
  funcionan con los mismos componentes, aunque los nombres de los paquetes cambian.
- **Windows (x64):** compatible desde la versión 1.21.0. PC/SC es el servicio de tarjetas
  inteligentes integrado. El middleware PKCS#11 es Thales Classic Client y FirmaUY carga el módulo
  de 64 bits.
- **macOS:** no está soportado ni probado.

### Python

Python 3.11 o posterior si instalás desde el código fuente. `uv tool install` trae su propio
intérprete, así que para la instalación recomendada no necesitás que el Python del sistema coincida.

## Instalar la pila de tarjetas

### Arch Linux

```bash
sudo pacman -S pcsclite ccid pcsc-tools opensc
sudo systemctl enable --now pcscd
```

`opensc` es opcional: aporta `opensc-tool` para diagnóstico y el backend PKCS#11 de OpenSC si elegís
ese camino.

### Debian y Ubuntu

```bash
sudo apt update
sudo apt install pcscd pcsc-tools libpcsclite1 libccid opensc
sudo systemctl enable --now pcscd
```

Si tu distribución no inicia `pcscd` automáticamente, habilitalo y arrancalo como se muestra.

### Windows

Conectá el lector. Windows inicia el servicio de tarjetas inteligentes (`SCardSvr`) cuando se
conecta un lector. Instalá el middleware de la cédula y su controlador desde la distribución
oficial. El módulo predeterminado es:

```text
C:\Program Files\Thales\Classic Client\BIN\gclib.dll
```

La copia que está en `Program Files (x86)` es de 32 bits y un Python de 64 bits no puede cargarla.

## Instalar el middleware PKCS#11

El flujo estándar usa el módulo PKCS#11 de la cédula uruguaya, `libgclib.so`. En Arch Linux el
paquete de la comunidad en AUR empaqueta el controlador oficial:

```bash
yay -S cedula-uruguay-pkcs11
```

Es un paquete de la comunidad, no un paquete oficial del Estado. Instala:

```text
/usr/lib/pkcs11/libgclib.so
```

Usá la versión 7.5.0-2 o posterior; las versiones anteriores podían hacer caer el proceso cuando se
ingresaba un PIN incorrecto.

Si preferís un módulo totalmente abierto, el backend OpenSC funciona con una compilación de
desarrollo. Mirá [backend OpenSC](https://carlosplanchon.github.io/firmauy/en/opensc-backend/). El modo
nativo (`--native`) evita el middleware por completo y se comunica con la tarjeta por PC/SC.

## Instalar FirmaUY

La instalación recomendada es una herramienta aislada:

```bash
uv tool install firmauy
```

Con pip, instalá en el entorno actual:

```bash
pip install firmauy
```

Instalar el paquete de Python **no** instala la pila de tarjetas. El servicio del lector y el módulo
PKCS#11, o el camino nativo, siguen siendo necesarios.

Para actualizar:

```bash
uv tool upgrade firmauy
```

## Verificar la instalación

```bash
firmauy --version
firmauy doctor
```

`doctor` informa PASS, WARN o FAIL para cada requisito e imprime una sugerencia de arreglo. Los
avisos no hacen fallar el comando; los FAIL terminan con estado 1. Una instalación sana termina con:

```text
All checks passed.
```

Para el camino nativo, diagnosticá el lector y la tarjeta en lugar del middleware:

```bash
firmauy doctor --native
```

Listá lo que ve el sistema:

```bash
firmauy list-readers
firmauy list-tokens
firmauy list-certs
```

## Firmar y verificar un primer documento

Usá cualquier PDF que tengas. La firma pide el PIN y no lo muestra:

```bash
firmauy sign-pdf documento.pdf
firmauy verify documento_firmado.pdf
```

La salida predeterminada es `documento_firmado.pdf`. La verificación devuelve:

- `0` para VALID.
- `1` para INVALID.
- `2` para INDETERMINATE, cuando la integridad se mantiene pero no se pudo establecer la confianza.

Si necesitás resultados legibles por una máquina, usá la API de Python o `--json`.

## Opciones frecuentes

### Elegir el backend de la tarjeta

```bash
firmauy sign-pdf documento.pdf --native
firmauy sign-pdf documento.pdf --pkcs11-lib /ruta/a/libgclib.so
firmauy sign-pdf documento.pdf --native --reader "ACS ACR39U 00 00"
```

`--native` no necesita middleware PKCS#11. `--reader` solo se aplica con `--native`.

### Elegir el certificado

Si el token expone más de un certificado de firma:

```bash
firmauy list-certs
firmauy sign-pdf documento.pdf --cert-id 0123456789abcdef
```

`--cert-id` se rechaza con `--native`, porque el backend nativo tiene un solo certificado de firma y
no puede cumplir la garantía de fijación.

### Orígenes del PIN

```bash
# Pregunta oculta, el comportamiento predeterminado
firmauy sign-pdf documento.pdf

# Descriptor de archivo heredado, recomendado para automatización
firmauy sign-pdf documento.pdf --pin-source fd --pin-fd 3 3< pin.txt

# Entrada estándar
printf '%s\n' "$PIN" | firmauy sign-pdf documento.pdf --pin-source stdin

# Variable de entorno
firmauy sign-pdf documento.pdf --pin-source env --pin-env-var FIRMAUY_PIN
```

No existe la opción `--pin`. Un PIN en `argv` queda visible en la lista de procesos y en el
historial del shell.

### Salida y sobrescritura

```bash
firmauy sign-pdf documento.pdf firmados/documento.pdf
firmauy sign-pdf documento.pdf firmados/documento.pdf --overwrite
```

Un archivo de salida existente se rechaza sin `--overwrite`, y el rechazo ocurre antes de contactar
la tarjeta.

## Solución de problemas

Ejecutá `firmauy doctor` primero. Las fallas más comunes y sus arreglos:

| Síntoma | Causa probable | Arreglo |
|---|---|---|
| `Could not reach the PC/SC daemon` | `pcscd` no está corriendo | `sudo systemctl enable --now pcscd` |
| `No PC/SC readers found` | Lector desconectado o no soportado | Reconectalo y probá con `pcsc-tools` |
| `No card found in reader` | Tarjeta no insertada o ilegible | Volvé a insertar la cédula |
| `PKCS#11 module not found` | Ruta incorrecta o paquete faltante | Instalá el middleware y ejecutá `doctor` |
| `No valid certificate with available private key` | Tarjeta equivocada o certificado vencido | Revisá `list-certs`; renová la cédula si hace falta |
| `Only 1 PIN try left` | Intentos incorrectos anteriores | Desbloqueá la cédula antes de reintentar |
| `PIN is blocked` | Demasiados intentos incorrectos | Desbloqueá por el canal de la autoridad emisora |
| Se encontraron varios lectores | Hay más de un lector conectado | Pasá `--reader` con un nombre de `list-readers` |
| Dos operaciones con la tarjeta chocan | Otra sesión de firma tiene la tarjeta | Cerrá el otro comando y reintentá |

No reintentes un PIN incorrecto a ciegas. Cada intento cuenta y un PIN bloqueado necesita el PUK.

## Siguientes pasos

- [Guía de uso](uso.md) para todos los comandos y opciones.
- [Seguridad y claves](seguridad.md) para el modelo de amenazas y el manejo del PIN.
- [Recetario](recetario.md) para automatización y privacidad.

