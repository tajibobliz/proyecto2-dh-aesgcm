"""Pruebas de generacion de primos y del grupo Diffie-Hellman."""

import pytest

from nucleo.aritmetica import exp_mod
from nucleo.primalidad import es_primo
from nucleo.primos import (
    GrupoDH,
    encontrar_generador,
    generar_grupo,
    generar_primo,
    generar_primo_seguro,
    validar_grupo,
)


def test_generar_primo_tiene_el_tamano_pedido():
    for bits in (64, 128, 256):
        p = generar_primo(bits)
        assert p.bit_length() == bits
        assert es_primo(p)


def test_primo_seguro_tiene_forma_2q_mas_1():
    p, q = generar_primo_seguro(128)
    assert p == 2 * q + 1
    assert p.bit_length() == 128
    assert es_primo(p) and es_primo(q)


def test_generador_tiene_orden_q():
    p, q = generar_primo_seguro(128)
    g = encontrar_generador(p, q)
    assert 1 < g < p - 1
    assert exp_mod(g, q, p) == 1       # g^q = 1: el orden divide a q
    assert exp_mod(g, 2, p) != 1       # el orden no es 2, entonces es q


def test_grupo_conocido_p23():
    # Ejemplo de libro: p = 23 = 2*11 + 1, y g = 4 tiene orden 11.
    assert exp_mod(4, 11, 23) == 1
    validar_grupo(GrupoDH(p=23, q=11, g=4))


def test_generar_grupo_pasa_la_validacion():
    grupo = generar_grupo(128)
    assert grupo.bits == 128
    validar_grupo(grupo)


def test_validar_grupo_rechaza_parametros_maliciosos():
    grupo = generar_grupo(128)
    p, q, g = grupo.p, grupo.q, grupo.g

    with pytest.raises(ValueError):                    # p no es 2q + 1
        validar_grupo(GrupoDH(p=p + 2, q=q, g=g))
    with pytest.raises(ValueError):                    # g trivial
        validar_grupo(GrupoDH(p=p, q=q, g=1))
    with pytest.raises(ValueError):                    # g de orden 2
        validar_grupo(GrupoDH(p=p, q=q, g=p - 1))
    with pytest.raises(ValueError):                    # p compuesto
        validar_grupo(GrupoDH(p=2 * 15 + 1 + 4, q=15, g=2))


def test_tamanos_demasiado_chicos_son_rechazados():
    with pytest.raises(ValueError):
        generar_primo(8)
    with pytest.raises(ValueError):
        generar_primo_seguro(16)
