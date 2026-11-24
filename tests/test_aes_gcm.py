"""Pruebas de AES-256 y GCM propios: vectores oficiales (FIPS 197 y
NIST SP 800-38D) y comparacion contra la libreria 'cryptography', que se
usa SOLO aqui como oraculo de verificacion."""

import secrets

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from simetrico.aes import AES256, CAJA_S, expandir_clave, gf_mult
from simetrico.gcm import AESGCMPropio, EtiquetaInvalida, gf128_mult


# ---------------------------------------------------------------- GF(2^8)
def test_multiplicacion_gf256_ejemplo_fips197():
    # FIPS 197, seccion 4.2: {57} * {83} = {c1} y {57} * {13} = {fe}
    assert gf_mult(0x57, 0x83) == 0xC1
    assert gf_mult(0x57, 0x13) == 0xFE


def test_todo_elemento_no_nulo_tiene_inverso():
    for a in range(1, 256):
        assert any(gf_mult(a, b) == 1 for b in range(1, 256))


def test_caja_s_calculada_coincide_con_el_estandar():
    assert CAJA_S[0x00] == 0x63
    assert CAJA_S[0x01] == 0x7C
    assert CAJA_S[0x53] == 0xED                 # ejemplo de FIPS 197
    assert CAJA_S[0xFF] == 0x16
    assert sorted(CAJA_S) == list(range(256))   # es una permutacion
    assert all(CAJA_S[a] != a for a in range(256))   # sin puntos fijos


# ---------------------------------------------------------------- AES-256
def test_expansion_de_clave_fips197_apendice_a3():
    clave = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                          "1f352c073b6108d72d9810a30914dff4")
    subclaves = expandir_clave(clave)
    assert len(subclaves) == 240
    assert subclaves[32:36].hex() == "9ba35411"         # w[8]
    assert subclaves[-4:].hex() == "706c631e"           # w[59]


def test_vector_fips197_apendice_c3():
    clave = bytes(range(32))
    claro = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES256(clave).cifrar_bloque(claro).hex() == "8ea2b7ca516745bfeafc49904b496089"


def test_aes_igual_a_la_libreria():
    for _ in range(30):
        clave, bloque = secrets.token_bytes(32), secrets.token_bytes(16)
        referencia = Cipher(algorithms.AES(clave), modes.ECB()).encryptor()
        assert AES256(clave).cifrar_bloque(bloque) == referencia.update(bloque)


def test_aes_rechaza_tamanos_incorrectos():
    with pytest.raises(ValueError):
        AES256(bytes(16))
    with pytest.raises(ValueError):
        AES256(bytes(32)).cifrar_bloque(bytes(15))


# ---------------------------------------------------------------- GF(2^128)
def test_gf128_propiedades():
    uno = 1 << 127                              # el "1" en la notacion de GCM
    for _ in range(20):
        a, b, c = (secrets.randbits(128) for _ in range(3))
        assert gf128_mult(a, uno) == a                                  # neutro
        assert gf128_mult(a, b) == gf128_mult(b, a)                     # conmutativa
        assert gf128_mult(a, b ^ c) == gf128_mult(a, b) ^ gf128_mult(a, c)  # distributiva
        assert gf128_mult(a, 0) == 0


# ---------------------------------------------------------------- GCM
def test_gcm_nist_caso_13():
    # Clave de 256 bits en cero, sin texto: solo etiqueta.
    salida = AESGCMPropio(bytes(32)).encrypt(bytes(12), b"", None)
    assert salida.hex() == "530f8afbc74536b9a963b4f1c4cb738b"


def test_gcm_nist_caso_14():
    salida = AESGCMPropio(bytes(32)).encrypt(bytes(12), bytes(16), None)
    assert salida[:16].hex() == "cea7403d4d606b6e074ec5d3baf39d18"     # cifrado
    assert salida[16:].hex() == "d0d1c8a799996bf0265b98b5d48ab919"     # etiqueta


@pytest.mark.parametrize("largo", [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000])
def test_gcm_igual_a_la_libreria(largo):
    clave, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    claro = secrets.token_bytes(largo)
    asociado = secrets.token_bytes(secrets.randbelow(40))
    propio = AESGCMPropio(clave).encrypt(nonce, claro, asociado)
    assert propio == AESGCM(clave).encrypt(nonce, claro, asociado)
    assert AESGCMPropio(clave).decrypt(nonce, propio, asociado) == claro


def test_gcm_detecta_cualquier_alteracion():
    clave, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    gcm = AESGCMPropio(clave)
    salida = gcm.encrypt(nonce, b"transferir 100 Bs", b"cabecera")
    for posicion in range(len(salida)):          # cada byte, cifrado y etiqueta
        alterada = bytearray(salida)
        alterada[posicion] ^= 0x01
        with pytest.raises(EtiquetaInvalida):
            gcm.decrypt(nonce, bytes(alterada), b"cabecera")
    with pytest.raises(EtiquetaInvalida):        # datos asociados distintos
        gcm.decrypt(nonce, salida, b"cabecerA")
    with pytest.raises(EtiquetaInvalida):        # nonce distinto
        gcm.decrypt(secrets.token_bytes(12), salida, b"cabecera")


def test_nonce_repetido_filtra_el_xor_de_los_textos():
    """Por que el nonce no debe repetirse: con el mismo flujo de claves,
    C1 xor C2 = P1 xor P2. Conociendo P1 se obtiene P2 sin la clave."""
    gcm = AESGCMPropio(secrets.token_bytes(32))
    nonce = bytes(12)
    p1, p2 = b"mensaje publico!", b"clave: 98765432"
    c1 = gcm.encrypt(nonce, p1, None)[:16]
    c2 = gcm.encrypt(nonce, p2, None)[:15]
    recuperado = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))
    assert recuperado == p2


def test_gcm_nonce_invalido():
    with pytest.raises(ValueError):
        AESGCMPropio(bytes(32)).encrypt(bytes(8), b"hola", None)


def test_borrar_elimina_las_subclaves():
    gcm = AESGCMPropio(secrets.token_bytes(32))
    gcm.borrar()
    assert gcm._aes._subclaves == bytearray(240)
    assert gcm._h == 0
