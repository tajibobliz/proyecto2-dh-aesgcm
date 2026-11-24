"""Pruebas de HMAC y HKDF con los vectores oficiales de los RFC 4231 y
5869, y contra el modulo hmac de Python como oraculo."""

import hashlib
import hmac
import secrets

import pytest

from hashing.hmac_hkdf import (
    comparar_constante,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    hmac_sha256,
    verificar_hmac,
)


def _hkdf_referencia(material, sal, info, longitud):
    """HKDF armado con la libreria estandar, solo para comparar."""
    prk = hmac.new(sal or bytes(32), material, hashlib.sha256).digest()
    salida, bloque, i = b"", b"", 1
    while len(salida) < longitud:
        bloque = hmac.new(prk, bloque + info + bytes([i]), hashlib.sha256).digest()
        salida += bloque
        i += 1
    return salida[:longitud]


def test_hmac_rfc4231_caso_1():
    etiqueta = hmac_sha256(bytes([0x0B] * 20), b"Hi There")
    assert etiqueta.hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")


def test_hmac_rfc4231_caso_2():
    etiqueta = hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    assert etiqueta.hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")


def test_hmac_igual_a_la_libreria_estandar():
    # Incluye claves mas largas que el bloque (se resumen primero).
    for largo_clave in (0, 1, 16, 32, 63, 64, 65, 100, 200):
        clave = secrets.token_bytes(largo_clave)
        mensaje = secrets.token_bytes(secrets.randbelow(500))
        esperado = hmac.new(clave, mensaje, hashlib.sha256).digest()
        assert hmac_sha256(clave, mensaje) == esperado, largo_clave


def test_verificar_hmac_detecta_alteraciones():
    clave = secrets.token_bytes(32)
    mensaje = b"transferir 100 Bs a la cuenta 12345"
    etiqueta = hmac_sha256(clave, mensaje)

    assert verificar_hmac(clave, mensaje, etiqueta)
    assert not verificar_hmac(clave, b"transferir 900 Bs a la cuenta 12345", etiqueta)
    assert not verificar_hmac(secrets.token_bytes(32), mensaje, etiqueta)
    alterada = bytes([etiqueta[0] ^ 1]) + etiqueta[1:]      # un solo bit
    assert not verificar_hmac(clave, mensaje, alterada)


def test_comparar_constante():
    assert comparar_constante(b"abc", b"abc")
    assert not comparar_constante(b"abc", b"abd")
    assert not comparar_constante(b"abc", b"abcd")
    assert comparar_constante(b"", b"")


def test_hkdf_rfc5869_caso_1():
    material = bytes([0x0B] * 22)
    sal = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))

    prk = hkdf_extract(sal, material)
    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    assert hkdf_expand(prk, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")


def test_hkdf_rfc5869_caso_3_sin_sal_ni_info():
    okm = hkdf(bytes([0x0B] * 22), sal=b"", info=b"", longitud=42)
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8")


def test_hkdf_igual_a_la_referencia():
    for longitud in (1, 16, 32, 33, 64, 100):
        material = secrets.token_bytes(64)
        sal = secrets.token_bytes(16)
        info = b"ELC107 clave de sesion"
        assert hkdf(material, sal, info, longitud) == _hkdf_referencia(
            material, sal, info, longitud)


def test_hkdf_separacion_de_dominios():
    secreto = secrets.token_bytes(32)
    k1 = hkdf(secreto, info=b"cliente->servidor")
    k2 = hkdf(secreto, info=b"servidor->cliente")
    assert len(k1) == len(k2) == 32
    assert k1 != k2


def test_hkdf_longitud_invalida():
    prk = bytes(32)
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"", 0)
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"", 255 * 32 + 1)
