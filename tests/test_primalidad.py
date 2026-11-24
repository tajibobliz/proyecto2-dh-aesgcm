"""Pruebas de Miller-Rabin."""

from nucleo.primalidad import PRIMOS_PEQUENOS, es_primo


def test_criba_de_primos_pequenos():
    assert PRIMOS_PEQUENOS[:10] == [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    assert PRIMOS_PEQUENOS[-1] == 1999
    assert len(PRIMOS_PEQUENOS) == 303


def test_casos_borde():
    for n in (-7, 0, 1):
        assert not es_primo(n)
    assert es_primo(2)
    assert es_primo(3)
    assert not es_primo(4)


def test_coincide_con_division_de_prueba_hasta_5000():
    def primo_ingenuo(n: int) -> bool:
        return n >= 2 and all(n % d for d in range(2, int(n ** 0.5) + 1))

    for n in range(5000):
        assert es_primo(n) == primo_ingenuo(n), n


def test_numeros_de_carmichael_son_detectados():
    # Enganan al test de Fermat, pero no a Miller-Rabin.
    for n in (561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265):
        assert not es_primo(n), n


def test_primos_grandes_conocidos():
    assert es_primo(2**61 - 1)       # Mersenne
    assert es_primo(2**127 - 1)      # Mersenne
    assert es_primo(2**255 - 19)     # primo de Curve25519
    assert es_primo(2**521 - 1)      # Mersenne


def test_compuestos_grandes():
    assert not es_primo(2**127 + 1)
    assert not es_primo((2**61 - 1) * (2**127 - 1))   # producto de dos primos
    assert not es_primo((2**127 - 1) ** 2)            # cuadrado de un primo
