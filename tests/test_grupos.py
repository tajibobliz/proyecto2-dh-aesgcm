"""Verificacion de los grupos Diffie-Hellman incluidos."""

import pytest

from nucleo.aritmetica import exp_mod
from nucleo.primalidad import es_primo
from nucleo.primos import validar_grupo
from protocolo.grupos import (
    GRUPO_DEMO_512,
    GRUPO_DEMO_1024,
    GRUPO_RFC3526_2048,
    GRUPOS_SEGUROS,
    obtener_grupo,
)


def _arctan_inverso(x: int, uno: int) -> int:
    """arctan(1/x) en punto fijo, por la serie de Taylor."""
    total = termino = uno // x
    x2, n, signo = x * x, 3, -1
    while termino:
        termino //= x2
        total += signo * (termino // n)
        signo, n = -signo, n + 2
    return total


def _pi_por_2_a_la(bits: int) -> int:
    """floor(pi * 2^bits) con la formula de Machin y aritmetica entera."""
    extra = 64
    uno = 1 << (bits + extra)
    return (16 * _arctan_inverso(5, uno) - 4 * _arctan_inverso(239, uno)) >> extra


def test_primo_rfc3526_coincide_con_su_formula():
    # p = 2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476)
    esperado = 2**2048 - 2**1984 - 1 + 2**64 * (_pi_por_2_a_la(1918) + 124476)
    assert GRUPO_RFC3526_2048.p == esperado
    assert GRUPO_RFC3526_2048.bits == 2048


def test_grupo_rfc3526_es_valido():
    grupo = GRUPO_RFC3526_2048
    assert es_primo(grupo.p, rondas=8)
    assert es_primo(grupo.q, rondas=8)
    assert grupo.g == 2
    assert exp_mod(grupo.g, grupo.q, grupo.p) == 1     # g tiene orden q


@pytest.mark.parametrize("grupo, bits", [(GRUPO_DEMO_512, 512), (GRUPO_DEMO_1024, 1024)])
def test_grupos_demo_generados_con_codigo_propio(grupo, bits):
    assert grupo.bits == bits
    validar_grupo(grupo, rondas=8)


def test_registro_y_politica():
    assert obtener_grupo("rfc3526-2048") is GRUPO_RFC3526_2048
    assert GRUPOS_SEGUROS == {"rfc3526-2048"}          # los demo no son seguros
    with pytest.raises(ValueError):
        obtener_grupo("inexistente")
