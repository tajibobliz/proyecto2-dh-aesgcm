"""Pruebas de SHA-256: vectores oficiales del NIST y comparacion contra
hashlib, que se usa SOLO aqui como oraculo de verificacion."""

import hashlib
import secrets

from hashing.sha256 import H0, K, SHA256, sha256


def test_constantes_derivadas_coinciden_con_el_estandar():
    assert H0[0] == 0x6A09E667 and H0[7] == 0x5BE0CD19
    assert K[0] == 0x428A2F98 and K[1] == 0x71374491 and K[63] == 0xC67178F2
    assert len(H0) == 8 and len(K) == 64


def test_vectores_nist():
    assert sha256(b"").hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    mensaje = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    assert sha256(mensaje).hex() == (
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")


def test_todas_las_longitudes_cerca_del_borde_de_bloque():
    # El relleno es la parte mas facil de implementar mal: se prueban
    # todas las longitudes de 0 a 200 bytes (cruza varios bordes de 64).
    for n in range(201):
        datos = secrets.token_bytes(n)
        assert sha256(datos) == hashlib.sha256(datos).digest(), n


def test_mensajes_grandes_aleatorios():
    for _ in range(5):
        datos = secrets.token_bytes(secrets.randbelow(20000) + 1000)
        assert sha256(datos) == hashlib.sha256(datos).digest()


def test_un_millon_de_letras_a():
    # Vector clasico del NIST.
    assert sha256(b"a" * 1_000_000).hex() == (
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")


def test_calculo_incremental_equivale_al_directo():
    datos = secrets.token_bytes(1000)
    h = SHA256()
    for i in range(0, 1000, 37):               # trozos de tamano irregular
        h.update(datos[i:i + 37])
    assert h.digest() == sha256(datos)
    assert h.digest() == h.digest()            # digest() no altera el estado
    assert h.hexdigest() == hashlib.sha256(datos).hexdigest()


def test_efecto_avalancha():
    a = int.from_bytes(sha256(b"Diffie-Hellman"), "big")
    b = int.from_bytes(sha256(b"Diffie-Hellmao"), "big")
    bits_distintos = bin(a ^ b).count("1")
    assert 90 < bits_distintos < 166           # cerca de 128 de 256
