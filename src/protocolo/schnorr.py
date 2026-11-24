"""Firma digital de Schnorr sobre el mismo grupo (p, q, g) de Diffie-Hellman.

Una firma digital prueba que un mensaje fue emitido por el dueno de una
clave privada y que no fue modificado. En este proyecto se usa para
autenticar el intercambio Diffie-Hellman y frenar el ataque de
intermediario (Man-in-the-Middle).

Claves:
    privada x aleatoria en [1, q-1]        publica y = g^x mod p

Firmar el mensaje m:
    1. k aleatorio en [1, q-1]             (nonce: un solo uso)
    2. r = g^k mod p
    3. e = H(r || y || m) mod q
    4. s = (k + x*e) mod q
    La firma es el par (e, s).

Verificar:
    1. r' = g^s * y^(q-e) mod p            (y^(q-e) = y^-e porque y^q = 1)
    2. Aceptar si H(r' || y || m) mod q == e

Por que funciona:
    g^s * y^-e = g^(k + x*e) * g^(-x*e) = g^k = r

Seguridad: se basa en el logaritmo discreto, igual que Diffie-Hellman.
El nonce k debe ser secreto y distinto en cada firma: si se repite, la
clave privada se despeja con algebra simple (ver tests/test_schnorr.py).
"""

import secrets
from dataclasses import dataclass

from hashing.sha256 import sha256
from nucleo.aritmetica import exp_mod
from nucleo.primos import GrupoDH
from protocolo.codificacion import bytes_a_int, codificar, int_a_bytes
from protocolo.dh import tam_bytes, validar_clave_publica
from protocolo.errores import ErrorProtocolo


@dataclass(frozen=True)
class Firma:
    e: int
    s: int


def generar_claves(grupo: GrupoDH) -> tuple[int, int]:
    """Devuelve (privada, publica) para firmar."""
    privada = 1 + secrets.randbelow(grupo.q - 1)
    return privada, exp_mod(grupo.g, privada, grupo.p)


def _desafio(grupo: GrupoDH, r: int, publica: int, mensaje: bytes) -> int:
    """e = H(r || y || m) mod q. Incluir y liga la firma a su clave."""
    n = tam_bytes(grupo)
    resumen = sha256(codificar(int_a_bytes(r, n), int_a_bytes(publica, n), mensaje))
    return bytes_a_int(resumen) % grupo.q


def firmar(grupo: GrupoDH, privada: int, mensaje: bytes,
           _k: int | None = None) -> Firma:
    """Firma 'mensaje' con la clave privada.

    El parametro _k existe solo para que las pruebas puedan demostrar el
    ataque por reutilizacion de nonce. En uso normal nunca se pasa.
    """
    publica = exp_mod(grupo.g, privada, grupo.p)
    k = _k if _k is not None else 1 + secrets.randbelow(grupo.q - 1)
    r = exp_mod(grupo.g, k, grupo.p)
    e = _desafio(grupo, r, publica, mensaje)
    s = (k + privada * e) % grupo.q
    return Firma(e=e, s=s)


def verificar(grupo: GrupoDH, publica: int, mensaje: bytes, firma: Firma) -> bool:
    """True si 'firma' es valida para 'mensaje' bajo la clave publica."""
    try:
        validar_clave_publica(grupo, publica)
    except ErrorProtocolo:
        return False
    if not (0 <= firma.e < grupo.q and 0 <= firma.s < grupo.q):
        return False

    # r' = g^s * y^(-e) mod p, con y^(-e) calculado como y^(q-e).
    r = (exp_mod(grupo.g, firma.s, grupo.p)
         * exp_mod(publica, grupo.q - firma.e, grupo.p)) % grupo.p
    return _desafio(grupo, r, publica, mensaje) == firma.e
