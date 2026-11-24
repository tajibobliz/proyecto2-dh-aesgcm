"""Pruebas de la aritmetica modular. Se compara contra pow() de Python,
que se usa SOLO aqui como oraculo para validar la implementacion propia."""

import secrets

import pytest

from nucleo.aritmetica import euclides_extendido, exp_mod, inverso_mod, mcd


def test_exp_mod_casos_conocidos():
    assert exp_mod(2, 10, 1000) == 24
    assert exp_mod(3, 0, 7) == 1
    assert exp_mod(0, 5, 7) == 0
    assert exp_mod(5, 3, 1) == 0


def test_exp_mod_igual_a_pow_con_numeros_grandes():
    for _ in range(50):
        base = secrets.randbits(512)
        exponente = secrets.randbits(512)
        modulo = secrets.randbits(512) | 1
        assert exp_mod(base, exponente, modulo) == pow(base, exponente, modulo)


def test_exp_mod_rechaza_entradas_invalidas():
    with pytest.raises(ValueError):
        exp_mod(2, -1, 7)
    with pytest.raises(ValueError):
        exp_mod(2, 3, 0)


def test_mcd():
    assert mcd(48, 18) == 6
    assert mcd(17, 5) == 1
    assert mcd(0, 9) == 9


def test_euclides_extendido_cumple_bezout():
    for _ in range(50):
        a = secrets.randbits(256) + 1
        b = secrets.randbits(256) + 1
        g, x, y = euclides_extendido(a, b)
        assert g == mcd(a, b)
        assert a * x + b * y == g


def test_inverso_mod():
    assert inverso_mod(17, 3120) == 2753
    for _ in range(50):
        m = secrets.randbits(256) | 1
        a = secrets.randbelow(m - 2) + 2
        if mcd(a, m) != 1:
            continue
        assert (a * inverso_mod(a, m)) % m == 1


def test_inverso_mod_inexistente():
    with pytest.raises(ValueError):
        inverso_mod(6, 9)
