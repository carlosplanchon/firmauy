# Seguridad y manejo de claves

Esta página explica cómo FirmaUY protege la clave de firma, el PIN y los documentos que maneja, y
qué amenazas quedan fuera de su control. Está pensada para operadores, integradores y revisores que
necesitan decidir si la herramienta es adecuada para su uso.

La versión corta: **la clave privada nunca sale de la cédula**. FirmaUY no importa, exporta ni
genera claves. Le pide a la tarjeta que firme y la tarjeta devuelve una firma. El PIN solo habilita
esa operación, nunca se almacena y se controla antes de enviarlo para que un error de tipeo no
gaste uno de los pocos intentos disponibles.

## Activos y límites

| Activo | Dónde vive | Quién puede leerlo | Rol de FirmaUY |
|---|---|---|---|
| Clave privada RSA | Dentro del elemento seguro de la cédula | Solo la tarjeta | Nunca la lee; pide que la tarjeta firme |
| PIN | En la memoria de la persona; brevemente en la memoria del proceso | La persona titular | Lo pide, lo valida, lo envía una vez y lo descarta |
| Certificado de firma | Público, en la tarjeta (objeto PKCS#11 o EF B001) | Cualquiera | Lo lee para mostrar al firmante y validarlo |
| Documentos a firmar | Sistema de archivos local | El usuario que ejecuta | Los lee, los firma y escribe junto a la entrada |
| Anclas de confianza | Certificados públicos incluidos, fijados por SHA-256 | Cualquiera | Los usa para verificar cadenas |
| Datos de identidad y foto | Archivos AIS públicos de la tarjeta | Cualquiera con la tarjeta | Los lee solo cuando se piden; permite redacción |

Hay cuatro límites, y cada uno tiene un mecanismo de aplicación distinto:

1. **Límite criptográfico.** La clave privada RSA se genera al emitir la cédula y la tarjeta la
   marca como no extraíble. Firmar es un comando que se envía a la tarjeta; el equipo recibe solo la
   firma. Esta es la propiedad más importante y la que FirmaUY no puede debilitar.
2. **Límite de proceso.** FirmaUY se ejecuta como el usuario que lo invoca, abre solo los archivos
   que se le indican y escribe solo la salida que se le pide. No se convierte en demonio, no
   escucha en un socket ni se ejecuta con privilegios elevados.
3. **Límite del sistema operativo.** La propiedad, el modo y las ACL de la salida firmada se
   conservan cuando la plataforma lo permite. Los archivos temporales se crean de forma privada y
   se confirman de forma atómica.
4. **Límite de red.** La firma y la verificación funcionan sin conexión. Los únicos pedidos
   salientes son un sellado de tiempo RFC 3161 y datos de revocación, y solo cuando el usuario los
   pide.

## Ciclo de vida de la clave

La clave la crea la autoridad certificadora uruguaya cuando se emite la cédula. Se guarda en el
elemento seguro de la tarjeta y la tarjeta expone solo tres operaciones al equipo: presentar el
certificado, habilitar la firma con el PIN de usuario y firmar un resumen. La tarjeta no entrega el
material de la clave al middleware PKCS#11, al lector ni a FirmaUY.

FirmaUY aplica el límite de tres formas:

* **Sin API de claves.** El código no tiene operaciones de importación, exportación, generación,
  respaldo ni recuperación de claves privadas. `list-certs` y `list-tokens` leen solo objetos
  públicos. El código PKCS#11 busca un objeto de clave por ID y lo entrega a `PKCS11Signer` de
  pyHanko; nunca pide `CKA_VALUE` ni marca una clave como extraíble.
* **Sin clave en memoria.** En modo nativo el equipo calcula el hash de los bytes a firmar y envía
  el resumen a la tarjeta con `PSO:HASH`. La tarjeta arma el DigestInfo de PKCS#1 y devuelve una
  firma RSA. El equipo nunca tiene la clave, ni siquiera descifrada.
* **Sin clave privada en la salida.** Los archivos PDF, XML y `.p7s` firmados contienen la firma y
  la cadena de certificados, que son públicos, y nunca la clave.

La contracara es que FirmaUY no puede recuperar una clave perdida o bloqueada. Desbloquear el PIN
requiere el PUK y los procedimientos de la autoridad emisora; FirmaUY no maneja el PUK.

## Manejo del PIN

El PIN es el único secreto que aporta el usuario. También es el activo que más fácil se pierde por
accidente, porque una cédula permite pocos intentos incorrectos antes de bloquearse.

### Orígenes aceptados

| Origen | Opción | Notas |
|---|---|---|
| Pregunta interactiva | `--pin-source prompt` (predeterminado) | Usa `getpass`, así que el PIN no se muestra |
| Variable de entorno | `--pin-source env --pin-env-var NOMBRE` | Cómodo para automatización; visible para el mismo usuario en el entorno del proceso |
| Entrada estándar | `--pin-source stdin` | Si stdin es una terminal, vuelve a la pregunta oculta; si no, lee una línea |
| Descriptor de archivo heredado | `--pin-source fd --pin-fd N` | Camino recomendado para automatización; el PIN no está en `argv`, en el entorno ni en el historial |

No existe a propósito una opción `--pin`. Un PIN pasado como argumento sería visible en la lista de
procesos y en el historial del shell, y quedaría capturado por la contabilidad de procesos.

La API de Python sigue la misma regla: pasá `pin_provider=` (una función sin argumentos) en lugar de
un PIN literal. La función se invoca recién después de que pasan las verificaciones del lector, del
certificado y del estado del PIN.

### Validación antes de tocar la tarjeta

Un PIN incorrecto no es gratis: consume un intento. Por eso FirmaUY rechaza la entrada mal formada
antes de abrir el token:

* Un PIN vacío se rechaza con la explicación de que igual contaría como intento.
* El PIN debe tener solo dígitos ASCII y entre 4 y 8 caracteres. Los dígitos Unicode que la tarjeta
  no acepta (`٤`, `④`) se rechazan, igual que las letras y los espacios.
* El camino PKCS#11 valida el formato de `--cert-id` antes del login.
* El certificado se revisa por vencimiento y por fecha de inicio de vigencia antes de pedir el PIN.

### Protección del contador de intentos

Ambos backends leen el estado del PIN antes de pedirlo:

* **Nativo:** un `VERIFY` vacío devuelve los intentos restantes sin consumir ninguno. Un PIN
  bloqueado, un solo intento restante o un contador ilegible abortan antes de la pregunta. La
  sonda se repite justo antes de enviar el PIN, así que `verify_pin` es seguro incluso si se llama
  por separado.
* **PKCS#11:** se revisan las banderas del PIN que informa el módulo antes del login. Los estados
  bloqueado y último intento se rechazan antes de la pregunta.

Un PIN incorrecto genera `IncorrectPinError` con `attempts_remaining` cuando el backend puede
conocerlo. El PIN nunca aparece en una excepción, en un registro, en un objeto de resultado ni en un
registro JSON.

### Duración de la sesión

La sesión PKCS#11 o PC/SC se abre para la operación de firma y se cierra en un bloque `finally`,
también cuando la firma falla. El PIN no se guarda entre comandos. Un proceso nuevo lo vuelve a
pedir.

## Backends de firma

### PKCS#11 (predeterminado)

El módulo indicado por `--pkcs11-lib` se carga desde una ruta explícita. FirmaUY abre el token, lee
los certificados públicos, valida el certificado elegido, inicia sesión con el PIN y firma a través
del módulo. El módulo y la tarjeta realizan la operación con la clave privada.

La confianza en este camino depende del middleware propietario. Un `libgclib.so` comprometido podría,
en principio, hacer todo lo que puede hacer el proceso. Instalalo desde una fuente confiable,
mantenelo actualizado y preferí el paquete de la distribución o el paquete de AUR que indica el
README. FirmaUY no puede auditar un middleware binario.

### PC/SC nativo (`--native`, y el valor predeterminado de la API)

El backend nativo envía APDUs ISO 7816-4 directamente a la tarjeta:

1. Selecciona el applet AIS.
2. Lee el certificado público de firma desde el EF B001.
3. Consulta el contador de intentos del PIN.
4. Verifica el PIN.
5. Selecciona la clave de firma con `MSE:SET DST`.
6. Envía el resumen SHA-256 con `PSO:HASH`.
7. Lee la firma RSA con `PSO:CDS`.

El certificado se revisa antes del PIN. La longitud de la firma se compara con el tamaño del módulo
RSA, así que una respuesta truncada de la tarjeta se convierte en error en lugar de una firma
inválida dentro de un documento firmado. El protocolo está documentado en el [protocolo de la
tarjeta](https://carlosplanchon.github.io/firmauy/en/card-protocol/).

El modo nativo saca al middleware propietario de la base de confianza y deja a la tarjeta, al
firmware del lector y al equipo como componentes que hay que confiar. No elimina las propiedades de
seguridad de la tarjeta y no hace que la clave sea exportable.

## Verificación y confianza

La verificación es local y sin conexión de forma predeterminada. La cadena se ancla en la raíz
nacional uruguaya y en el intermedio del Ministerio del Interior, que se incluyen como certificados
públicos y se fijan por SHA-256. Toda copia de esos certificados, ya sea incluida, cacheada o
descargada, debe coincidir con la huella; el intermedio también debe verificar contra la raíz. Por
eso el origen de los bytes no importa, y una copia alterada se rechaza.

El almacén de confianza del sistema operativo nunca se consulta. Con `--no-trust` se usa una lista
de anclas vacía explícita, así que un firmante cuya cadena llegue a una raíz confiada por el sistema
se informa igual como no confiable. El resultado de la validación es uno de estos:

* **VALID:** la integridad se mantiene y la cadena llega a un ancla confiable.
* **INVALID:** la integridad falla, o se sabe que la cadena no es confiable o está revocada.
* **INDETERMINATE:** la integridad se mantiene, pero no se pudo establecer la confianza o no se
  evaluó.

La verificación de revocación está apagada de forma predeterminada porque necesita red y un
respondedor CRL u OCSP alcanzable. Cuando se habilita, una consulta que falla o que la política de
salida rechaza no pasa en silencio: el motivo se informa en las filas de la cadena.

Los tokens de sellado de tiempo no se consideran confiables salvo que el usuario aporte anclas de
la TSA con `--tsa-ca`. Sin ellas, el sello se informa como presente pero no validado, y el `genTime`
del documento no se trata como una hora de firma confiable.

## Archivos de salida

Escribir el archivo firmado es un paso relevante para la seguridad: un nombre temporal predecible o
un enlace simbólico pueden convertirse en la sobrescritura de otro archivo.

* **La preparación es privada e impredecible.** La salida se escribe en un archivo nuevo creado con
  `O_CREAT | O_EXCL` en el directorio de destino, con modo `0o600` donde la plataforma lo permite.
  No se usa el antiguo `<nombre>.part` predecible.
* **La confirmación es atómica.** El archivo terminado recibe `fsync` y se mueve a su lugar con
  `os.replace`, o con un enlace duro donde la plataforma lo necesita. Un lector nunca ve un
  documento a medio escribir.
* **No se siguen enlaces simbólicos.** El archivo existente se abre con `O_NOFOLLOW` cuando está
  disponible; en Windows se detectan los puntos de reanálisis antes de abrir. Un enlace plantado en
  la ruta de salida se reemplaza, no se sigue.
* **Se conserva el control de acceso.** Al reemplazar un archivo regular existente, se copian al
  reemplazo su propietario, grupo, modo y ACL (donde se soportan). Si eso no se puede hacer, el
  comando falla en lugar de producir un archivo con permisos más débiles.
* **Los archivos existentes no se sobrescriben de forma predeterminada.** Hace falta `--overwrite`,
  y la comprobación se hace antes de firmar, así que una salida rechazada no consume un intento de
  PIN.

En Windows, el archivo firmado hereda los permisos de su carpeta y no se copia nada del archivo que
reemplaza. Está documentado en el README.

## Análisis de entradas y límites de recursos

Un documento es una entrada no confiable. Los analizadores tienen límites explícitos y valores
seguros:

| Entrada | Límite | Protección del analizador |
|---|---|---|
| XML (firma y verificación) | 16 MiB | Entidades externas deshabilitadas, red deshabilitada, sin árbol gigante, sin carga de DTD |
| PDF (verificación y control posterior) | 128 MiB | Tamaño revisado antes de analizar; profundidad del árbol de páginas acotada |
| CMS / `.p7s` (verificación) | 8 MiB | Tamaño revisado antes de analizar; los bytes finales se toleran solo donde el formato lo permite |
| Imagen del PDF para la apariencia | Decodificada al tamaño de la caja | Recursos de decodificación acotados; la imagen se revisa antes del PIN |
| Respuesta de la TSA | 4 MiB | Leída con un límite duro de bytes y un límite de tiempo |

En modo por lote, los archivos de entrada quedan confinados al directorio indicado. Una ruta que
intente salir de él, incluso mediante un enlace simbólico, se omite y se informa en lugar de
firmarse.

## Comportamiento de red

Firmar y verificar no requieren conexión. Dos funciones opcionales sí:

* `--tsa-url` envía el resumen de la firma a una autoridad de sellado de tiempo RFC 3161.
* `--check-revocation` descarga CRL, respuestas OCSP y certificados de emisor nombrados por
  certificados del documento o de la cadena.

Ambas usan la misma política de salida:

* **Solo destinos públicos de forma predeterminada.** Se rechazan loopback, redes privadas y
  direcciones link-local. Link-local se rechaza incluso con `--allow-private-network`, porque ahí
  responden los servicios de metadatos de la nube.
* **Resolución única.** El nombre se resuelve, se juzgan todas las direcciones y el socket se abre
  a la dirección que se juzgó. El DNS rebinding no puede cambiar una dirección interna entre la
  comprobación y la conexión.
* **Redirecciones acotadas y revisadas.** El pedido a la TSA no sigue redirecciones, porque puede
  llevar credenciales. Las consultas de revocación siguen como máximo tres, y cada destino se juzga
  igual que el primero.
* **Acotado.** Cada pedido tiene un límite de bytes y un límite de tiempo total. Una respuesta que
  excede el límite se rechaza, no se acumula sin control.
* **Sin credenciales ambientales.** Nunca se lee `~/.netrc`, así que los pedidos no pueden enviar
  credenciales guardadas a un host nombrado por un documento.

Las URL pueden venir de un documento o de un certificado no confiable. Por eso los valores
predeterminados son restrictivos y `--allow-private-network` es opt-in y se llama por lo que hace.

## Cadena de suministro e integridad de las versiones

* Las dependencias tienen pisos de seguridad, no rangos abiertos: `cryptography>=50.0.0`,
  `urllib3>=2.8.0`, `pyhanko>=0.35.1`, `lxml>=6.1.1`, entre otras. `urllib3` 2.8.0 es la primera
  versión que corrige tres avisos en el camino de respuesta que un servidor TSA o CRL malicioso
  podría alcanzar.
* `uv.lock` fija el grafo exacto de dependencias para desarrollo y CI.
* CI ejecuta lint, la matriz de pruebas (Linux y Windows, Python 3.11 a 3.14), el barrido de TSTInfo
  y el perfil profundo de propiedades.
* El flujo de publicación usa PyPI Trusted Publishing por OIDC. No hay un token de PyPI de larga
  duración en el repositorio. El flujo corre en un entorno `pypi` protegido, así que un push de tag
  puede exigir aprobación manual, y se niega a publicar si el tag y la versión del paquete no
  coinciden.
* Los certificados nacionales incluidos son públicos y están fijados por SHA-256. Su procedencia
  está en `src/firmauy/data/PROVENANCE.md`.

## Comportamiento que falla de forma segura

Las siguientes condiciones abortan en lugar de adivinar:

| Condición | Comportamiento |
|---|---|
| PIN bloqueado o en el último intento | No se pide el PIN ni se gasta un intento |
| Contador de intentos ilegible | Se niega a enviar el PIN |
| Certificado vencido o aún no vigente | Se rechaza antes del PIN |
| Certificado sin clave privada correspondiente | Se rechaza antes o durante la selección |
| La tarjeta devuelve una firma corta | Error; no se incrusta una firma inválida |
| La salida existe sin `--overwrite` | Se rechaza antes del PIN |
| No se pueden conservar los permisos de salida | Se rechaza; no se escribe con permisos más débiles |
| Entrada por encima de su límite | Se rechaza antes de analizar |
| Destino de red no público | Se rechaza antes de conectar, salvo habilitación explícita |
| Sin anclas bajo `--no-trust` | Se informa no confiable; nunca se cae al almacén del sistema |
| Respuesta de TSA por encima del límite | Se rechaza; no se analiza una respuesta truncada |

## Qué no protege FirmaUY

Las afirmaciones de seguridad solo son útiles cuando sus límites son claros. FirmaUY **no** protege
contra:

* Un equipo comprometido, un keylogger, un shell malicioso o un atacante que pueda leer la memoria
  del proceso mientras se usa el PIN.
* Un middleware PKCS#11 comprometido o un lector de tarjetas malicioso. El modo nativo saca al
  middleware de la base de confianza, pero sigue confiando en el lector y en la tarjeta.
* Una tarjeta robada con un PIN conocido. La tarjeta es el límite de seguridad, y posesión más PIN
  es autorización.
* Una TSA maliciosa o con puerta trasera. Los sellos solo son confiables cuando el usuario aporta
  las anclas de la TSA.
* Un visor de PDF o XML malicioso que maneje mal un archivo correctamente firmado.
* Validez legal, acreditación o certificación. Un resultado VALID es una evaluación técnica, no
  legal. Para eso usá el validador oficial en <https://firma.gub.uy/>.
* El PUK, el desbloqueo, la renovación o la revocación del certificado de la persona titular.
* La confidencialidad de los documentos después de firmarlos. FirmaUY no cifra documentos ni borra
  los originales.

## Lista de uso seguro

1. Instalá desde PyPI o desde este repositorio, y mantené actualizados el equipo, la pila del lector
   y el middleware PKCS#11.
2. Preferí la pregunta oculta para uso interactivo. En automatización, preferí `--pin-source fd` a
   una variable de entorno, y evitá el trazado del shell alrededor del comando.
3. Ejecutá `firmauy doctor` antes de la primera firma. No necesita PIN y detecta la mayoría de los
   problemas de instalación.
4. Firmá una copia, verificá localmente y subí el resultado al validador oficial cuando el documento
   importe.
5. Dejá `--check-revocation` apagado salvo que tengas una fuente de revocación alcanzable y
   confiable.
6. Aportá `--tsa-ca` cuando necesites un sello de tiempo que realmente puedas confiar.
7. Usá `--redact` al compartir la salida de `fetch-identity` o `fetch-photo`.
8. No ejecutes dos operaciones con la tarjeta en paralelo sobre el mismo lector. Las sesiones PC/SC
   chocan.
9. Tratá los archivos firmados como sensibles. La firma protege la integridad y el origen, no la
   confidencialidad.
10. Revisá las anclas que pasás con `--ca-file`. Son tuyas y FirmaUY no las fija.

## Estándares y controles

| Área | Estándar o práctica | Dónde se aplica |
|---|---|---|
| Comandos de tarjeta | ISO/IEC 7816-4, ICAO 9303 para la MRZ | `native_card.py`, `card_reader.py` |
| Interfaz del token | PKCS#11 | `pkcs11_utils.py`, `signing.py` |
| CMS / CAdES | RFC 5652 | `cms_sign.py`, `cms_verify.py` |
| PAdES | ETSI EN 319 142-1 | `signing.py`, pyHanko |
| XAdES | ETSI EN 319 132-1 | `xml_sign.py`, `xml_verify.py` |
| Sellado de tiempo | RFC 3161 | `signing.py`, `verify_common.py` |
| Validación de certificados | Validación de ruta RFC 5280 con anclas locales | `national_ca.py`, `verify_common.py` |
| Secretos | Sin secretos en `argv`, sin eco, sin registro, sin persistencia | `pin.py`, `signing.py` |
| Seguridad de archivos | Reemplazo atómico, sin seguir enlaces, permisos conservados | `signing.py` |
| Validación de entradas | Límites de tamaño, analizador XML seguro, confinamiento por lote | `xml_sign.py`, `pdf_verify.py`, `cms_verify.py` |
| Red | Regla de destinos, límites de redirección y tamaño, sin credenciales ambientales | `outbound.py` |
| Cadena de suministro | Dependencias fijadas, publicación OIDC, entorno protegido | `pyproject.toml`, `uv.lock`, flujo de publicación |

La suite de pruebas aplica estos controles con pruebas de regresión, incluidas las invariantes de
verificación de sellos de tiempo y las pruebas de integración con lector simulado.

## Reportar una vulnerabilidad

No abras un issue público por un problema de seguridad. Usá el reporte privado de vulnerabilidades
de GitHub en el repositorio original, como se describe en
[SECURITY.md](https://github.com/carlosplanchon/firmauy/blob/main/SECURITY.md). Se aceptan reportes
en español o en inglés.

