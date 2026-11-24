# Manual de despliegue y uso

Proyecto 2 - ELC107 Criptografia y Seguridad
Protocolo de intercambio de claves Diffie-Hellman y cifrado hibrido AES-256-GCM

## 1. Requisitos

- Python 3.11 o superior (`python --version`)
- Git (opcional, para clonar el repositorio)
- Sistema operativo: Windows, Linux o macOS

## 2. Instalacion

```bash
git clone <URL_DEL_REPOSITORIO>
cd proyecto2-dh-aesgcm

python -m venv .venv
```

Activar el entorno virtual:

| Sistema | Comando |
|---------|---------|
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (CMD) | `.venv\Scripts\activate.bat` |
| Linux / macOS | `source .venv/bin/activate` |

Instalar dependencias:

```bash
pip install -r requirements.txt
```

Dependencias: `cryptography` (solo para la primitiva AES-256-GCM) y `pytest`
(pruebas). Toda la logica asimetrica y de hash es implementacion propia.

Todos los comandos de este manual se ejecutan desde la carpeta raiz del
proyecto.

## 3. Verificar la instalacion

```bash
python -m pytest -v
```

Deben pasar todas las pruebas (tarda menos de un minuto).

## 4. Generar las identidades

Cada parte necesita un par de claves de firma. Se generan una sola vez:

```bash
python src/generar_identidades.py
```

Se crea la carpeta `claves/` con cuatro archivos:

| Archivo | Contenido | Quien lo tiene |
|---------|-----------|----------------|
| `servidor.json` | clave privada del servidor | solo el servidor |
| `servidor.pub.json` | clave publica del servidor | servidor y cliente |
| `cliente.json` | clave privada del cliente | solo el cliente |
| `cliente.pub.json` | clave publica del cliente | cliente y servidor |

Los archivos con clave privada estan excluidos del repositorio.

Para usar dos computadoras: copiar al equipo cliente `cliente.json` y
`servidor.pub.json`, y dejar en el servidor `servidor.json` y
`cliente.pub.json`.

## 5. Uso normal

Terminal 1, servidor:

```bash
python src/servidor.py
```

Terminal 2, cliente interactivo:

```bash
python src/cliente.py
```

Escribir mensajes y pulsar Enter. Linea vacia para salir. Para enviar
mensajes sin modo interactivo:

```bash
python src/cliente.py --mensaje "hola" --mensaje "segundo mensaje"
```

Opciones principales:

| Programa | Opcion | Significado | Valor por defecto |
|----------|--------|-------------|-------------------|
| servidor, cliente | `--host` | direccion IP | 127.0.0.1 |
| servidor, cliente | `--puerto` | puerto TCP | 5000 |
| servidor, cliente | `--claves` | carpeta de identidades | claves |
| servidor | `--permitir-anonimo` | acepta clientes sin firma (solo demo) | desactivado |
| cliente | `--anonimo` | conecta sin firma (solo demo) | desactivado |

Para dos computadoras en la misma red: iniciar el servidor con
`--host 0.0.0.0` y el cliente con `--host <IP_DEL_SERVIDOR>`.

## 6. Demostraciones de ataque

El atacante se ubica entre el cliente y el servidor. El servidor escucha en
el puerto 5000, el atacante en el 6000, y el cliente se conecta al 6000.

En todos los casos:

```bash
# Terminal 1
python src/servidor.py

# Terminal 2 (elegir el modo)
python src/atacante.py --modo <MODO>

# Terminal 3
python src/cliente.py --puerto 6000 --mensaje "transferir 100 Bs"
```

| Modo | Que hace el atacante | Resultado esperado |
|------|----------------------|--------------------|
| `pasivo` | Escucha todo el trafico | Ve A, B y el cifrado, pero no puede leer el mensaje |
| `alterar` | Cambia 1 bit del mensaje cifrado | El servidor lo rechaza: etiqueta GCM invalida |
| `repetir` | Reenvia un mensaje ya visto | El servidor lo rechaza: numero de secuencia repetido |
| `mitm` | Sustituye A y B por su propio valor | El cliente lo rechaza: firma del servidor invalida |

### Man-in-the-Middle exitoso (Diffie-Hellman sin autenticar)

Para mostrar por que la firma es necesaria, se desactiva la autenticacion:

```bash
# Terminal 1
python src/servidor.py --permitir-anonimo

# Terminal 2
python src/atacante.py --modo mitm

# Terminal 3
python src/cliente.py --anonimo --puerto 6000 --mensaje "mi clave bancaria es 1234"
```

El atacante muestra el mensaje en claro. El cliente y el servidor no notan
nada, pero sus huellas de sesion son distintas: cada uno comparte clave con
el atacante y no entre si.

## 7. Demostraciones por fase y rendimiento

```bash
python src/demo_fase1.py           # aritmetica modular, Miller-Rabin, primos seguros
python src/demo_fase2.py           # SHA-256, HMAC, HKDF
python src/medir_rendimiento.py    # tablas de tiempos + docs/resultados_rendimiento.csv
```

## 8. Estructura del proyecto

```
src/
  nucleo/        aritmetica modular, Miller-Rabin, primos seguros     (propio)
  hashing/       SHA-256, HMAC, HKDF                                  (propio)
  protocolo/     Diffie-Hellman, firma Schnorr, handshake             (propio)
                 canal_seguro.py: AES-256-GCM                         (libreria)
  red/           transporte TCP, servidor, cliente, atacante
  servidor.py, cliente.py, atacante.py      puntos de entrada
  generar_identidades.py, medir_rendimiento.py, demo_fase1.py, demo_fase2.py
tests/           pruebas unitarias y de extremo a extremo
docs/            diagramas, capturas y resultados
```

## 9. Problemas frecuentes

| Problema | Solucion |
|----------|----------|
| `No se encontraron las identidades` | Ejecutar `python src/generar_identidades.py` |
| `ModuleNotFoundError: cryptography` | Activar el entorno virtual y ejecutar `pip install -r requirements.txt` |
| `Address already in use` / el puerto esta ocupado | Cerrar el programa anterior o usar otro `--puerto` |
| `No se pudo conectar` | Verificar que el servidor este iniciado y que el puerto coincida |
| PowerShell no deja activar el entorno | `Set-ExecutionPolicy -Scope Process RemoteSigned` y reintentar |
| `Cliente no autorizado` | El servidor y el cliente usan carpetas `claves/` distintas: regenerar y copiar |
| `python` no se reconoce (Windows) | Probar con `py` en lugar de `python` |
