# Protocolo Diffie-Hellman y cifrado hibrido AES-256-GCM

Proyecto 2 - ELC107 Criptografia y Seguridad - UAGRM / FICCT

Canal de comunicacion seguro entre un cliente y un servidor sobre una red
insegura. Las dos partes acuerdan una clave con Diffie-Hellman sobre grupos
modulares, autentican el intercambio con firmas digitales y cifran los
mensajes con AES-256-GCM.

## Que esta implementado a mano

| Componente | Archivo | Estandar |
|------------|---------|----------|
| Exponenciacion modular, Euclides extendido | `src/nucleo/aritmetica.py` | - |
| Prueba de primalidad Miller-Rabin | `src/nucleo/primalidad.py` | - |
| Primos seguros y generador del grupo | `src/nucleo/primos.py` | - |
| SHA-256 | `src/hashing/sha256.py` | FIPS 180-4 |
| HMAC-SHA256 y HKDF | `src/hashing/hmac_hkdf.py` | RFC 2104, RFC 5869 |
| Intercambio Diffie-Hellman | `src/protocolo/dh.py` | RFC 3526 (grupo) |
| Firma digital de Schnorr | `src/protocolo/schnorr.py` | - |
| Handshake autenticado | `src/protocolo/handshake.py` | - |

Unica primitiva de libreria: AES-256-GCM (`cryptography`), por ser cifrado
simetrico. Las pruebas usan `hashlib` y `hmac` solo como referencia para
validar las implementaciones propias.

## Instalacion rapida

Requiere Python 3.11 o superior.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

## Uso rapido

```bash
python src/generar_identidades.py                  # una sola vez
python src/servidor.py                             # terminal 1
python src/cliente.py --mensaje "hola"             # terminal 2
```

Demostracion de ataque (el cliente pasa por el atacante en el puerto 6000):

```bash
python src/atacante.py --modo mitm                 # terminal 3
python src/cliente.py --puerto 6000 --mensaje "hola"
```

Modos de ataque: `pasivo`, `alterar`, `repetir`, `mitm`. La guia completa
esta en [MANUAL_DESPLIEGUE.md](MANUAL_DESPLIEGUE.md).

## Como funciona

```
Cliente                                               Servidor
a, A = g^a mod p                                      b, B = g^b mod p
1. hola:         grupo, A, nonce_c, identidad  --->
2. respuesta:    B, nonce_s, firma_servidor    <---
3. confirmacion: firma_cliente                 --->
4. listo                                       <---

secreto = g^(ab) mod p
T       = SHA-256(todo lo intercambiado)
claves  = HKDF(sal = T, material = secreto)      una por sentido
datos   = AES-256-GCM(clave, contador, mensaje)
```

## Propiedades de seguridad

| Propiedad | Mecanismo |
|-----------|-----------|
| Confidencialidad | AES-256-GCM con clave derivada de Diffie-Hellman |
| Integridad y autenticidad de mensajes | Etiqueta GCM de 128 bits (AEAD) |
| Autenticacion mutua, anti Man-in-the-Middle | Firma Schnorr sobre la transcripcion |
| Secreto perfecto hacia adelante | Claves Diffie-Hellman efimeras por sesion |
| Anti repeticion | Numero de secuencia por mensaje y nonces por sesion |
| Anti degradacion | El servidor solo acepta grupos de 2048 bits |
| Zero-Trust | Validacion de toda clave publica, parametro y mensaje recibido |
| Gestion de memoria | Claves en `bytearray`, borradas al cerrar la sesion |

## Estructura

```
src/nucleo/       aritmetica modular, primalidad, primos
src/hashing/      SHA-256, HMAC, HKDF
src/protocolo/    grupos, DH, Schnorr, canal AES-GCM, handshake, identidades
src/red/          transporte TCP, servidor, cliente, atacante
tests/            pruebas unitarias y de extremo a extremo
docs/             diagramas, capturas y resultados
```

## Integrantes

- Nombre completo - Registro
- Nombre completo - Registro
