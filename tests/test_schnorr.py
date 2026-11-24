"""Pruebas de la firma digital de Schnorr."""

import pytest

from nucleo.aritmetica import inverso_mod
from protocolo import schnorr
from protocolo.grupos import GRUPO_DEMO_512, GRUPO_RFC3526_2048


@pytest.mark.parametrize("grupo", [GRUPO_DEMO_512, GRUPO_RFC3526_2048])
def test_firma_valida_verifica(grupo):
    privada, publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"mensaje de prueba")
    assert schnorr.verificar(grupo, publica, b"mensaje de prueba", firma)


def test_mensaje_alterado_no_verifica():
    grupo = GRUPO_DEMO_512
    privada, publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"pagar 100 Bs")
    assert not schnorr.verificar(grupo, publica, b"pagar 900 Bs", firma)


def test_firma_alterada_no_verifica():
    grupo = GRUPO_DEMO_512
    privada, publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"hola")
    assert not schnorr.verificar(grupo, publica, b"hola", schnorr.Firma(firma.e, firma.s ^ 1))
    assert not schnorr.verificar(grupo, publica, b"hola", schnorr.Firma(firma.e ^ 1, firma.s))


def test_clave_publica_ajena_no_verifica():
    grupo = GRUPO_DEMO_512
    privada, _ = schnorr.generar_claves(grupo)
    _, otra_publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"hola")
    assert not schnorr.verificar(grupo, otra_publica, b"hola", firma)


def test_valores_fuera_de_rango_son_rechazados():
    grupo = GRUPO_DEMO_512
    privada, publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"hola")
    assert not schnorr.verificar(grupo, publica, b"hola", schnorr.Firma(firma.e, firma.s + grupo.q))
    assert not schnorr.verificar(grupo, publica, b"hola", schnorr.Firma(-1, firma.s))
    assert not schnorr.verificar(grupo, 1, b"hola", firma)             # clave trivial
    assert not schnorr.verificar(grupo, grupo.p - 1, b"hola", firma)   # orden 2


def test_dos_firmas_del_mismo_mensaje_son_distintas():
    # El nonce k es aleatorio: la firma no es determinista.
    grupo = GRUPO_DEMO_512
    privada, publica = schnorr.generar_claves(grupo)
    f1 = schnorr.firmar(grupo, privada, b"hola")
    f2 = schnorr.firmar(grupo, privada, b"hola")
    assert f1 != f2
    assert schnorr.verificar(grupo, publica, b"hola", f1)
    assert schnorr.verificar(grupo, publica, b"hola", f2)


def test_ataque_reutilizar_el_nonce_revela_la_clave_privada():
    """Si se firma dos veces con el mismo k:

        s1 = k + x*e1 (mod q)
        s2 = k + x*e2 (mod q)
        s1 - s2 = x * (e1 - e2)   =>   x = (s1 - s2) * (e1 - e2)^-1 (mod q)

    Un atacante que ve ambas firmas recupera la clave privada x.
    Por eso el nonce debe ser aleatorio y de un solo uso.
    """
    grupo = GRUPO_DEMO_512
    privada, _ = schnorr.generar_claves(grupo)
    k_repetido = 123456789

    f1 = schnorr.firmar(grupo, privada, b"mensaje uno", _k=k_repetido)
    f2 = schnorr.firmar(grupo, privada, b"mensaje dos", _k=k_repetido)

    q = grupo.q
    recuperada = ((f1.s - f2.s) * inverso_mod((f1.e - f2.e) % q, q)) % q
    assert recuperada == privada
