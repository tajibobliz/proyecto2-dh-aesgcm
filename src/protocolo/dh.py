"""Intercambio de claves Diffie-Hellman sobre el grupo (p, q, g).

Permite que dos partes acuerden un secreto por un canal que cualquiera
puede leer:

    Alice: a aleatorio,  A = g^a mod p   ---- A ---->
    Bob:   b aleatorio,  B = g^b mod p   <--- B -----
    Alice: s = B^a mod p
    Bob:   s = A^b mod p
    Ambos obtienen s = g^(ab) mod p

Un espia conoce p, g, A y B. Para obtener s tendria que resolver el
problema de Diffie-Hellman, que en la practica exige calcular un
logaritmo discreto (hallar 'a' a partir de g^a mod p). Con p de 2048
bits el mejor algoritmo conocido (criba del cuerpo de numeros) necesita
del orden de 2^112 operaciones: inviable.

Importante: Diffie-Hellman por si solo NO autentica. Un atacante activo
puede ponerse en el medio y negociar un secreto con cada parte. Eso se
resuelve firmando el intercambio (ver schnorr.py y handshake.py).
"""

import secrets
from dataclasses import dataclass

from nucleo.aritmetica import exp_mod
from nucleo.primos import GrupoDH
from protocolo.codificacion import int_a_bytes
from protocolo.errores import ErrorProtocolo


@dataclass
class ParClavesDH:
    """Par efimero: exponente privado y valor publico g^privada mod p."""

    privada: int
    publica: int

    @classmethod
    def generar(cls, grupo: GrupoDH) -> "ParClavesDH":
        # Exponente uniforme en [1, q-1], de un generador criptografico.
        privada = 1 + secrets.randbelow(grupo.q - 1)
        return cls(privada=privada, publica=exp_mod(grupo.g, privada, grupo.p))


def validar_clave_publica(grupo: GrupoDH, publica: int) -> None:
    """Verifica un valor publico recibido. Lanza ErrorProtocolo si no sirve.

    Sin esta validacion un atacante podria enviar:
    - 0 o 1: el secreto compartido seria 0 o 1, conocido por todos.
    - p - 1: el secreto solo podria valer 1 o p - 1.
    - un elemento fuera del subgrupo de orden q: filtraria informacion
      del exponente privado (ataque de confinamiento a subgrupo pequeno).

    La condicion publica^q = 1 (mod p) garantiza que el valor pertenece
    al subgrupo de orden primo q.
    """
    if not isinstance(publica, int) or not 1 < publica < grupo.p - 1:
        raise ErrorProtocolo("Clave publica fuera del rango (1, p-1)")
    if exp_mod(publica, grupo.q, grupo.p) != 1:
        raise ErrorProtocolo("Clave publica fuera del subgrupo de orden q")


def calcular_secreto(grupo: GrupoDH, privada: int, publica_ajena: int) -> bytearray:
    """Calcula el secreto compartido s = publica_ajena^privada mod p.

    Devuelve un bytearray de longitud fija para poder borrarlo despues.
    Este valor nunca se usa directo como clave: pasa primero por HKDF.
    """
    validar_clave_publica(grupo, publica_ajena)
    secreto = exp_mod(publica_ajena, privada, grupo.p)
    return bytearray(int_a_bytes(secreto, tam_bytes(grupo)))


def tam_bytes(grupo: GrupoDH) -> int:
    """Cantidad de bytes necesaria para representar un elemento del grupo."""
    return (grupo.p.bit_length() + 7) // 8
