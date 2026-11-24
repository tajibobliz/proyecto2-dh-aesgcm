"""Prueba de primalidad de Miller-Rabin.

Para saber si un numero de cientos de digitos es primo no se puede probar
divisor por divisor. Miller-Rabin es una prueba probabilistica:

- Si responde "compuesto", es compuesto con certeza.
- Si responde "primo", puede equivocarse con probabilidad <= 4^-rondas.
  Con 40 rondas el error es menor a 2^-80, despreciable en la practica.

Fundamento: si n es primo impar y n - 1 = 2^s * d (con d impar), entonces
para toda base a se cumple una de estas dos condiciones:

    a^d = 1 (mod n)
    a^(2^r * d) = -1 (mod n)   para algun r en [0, s)

Si una base 'a' no cumple ninguna, es un "testigo" de que n es compuesto.
A diferencia del test de Fermat, los numeros de Carmichael (561, 1105...)
no lo enganan.
"""

import secrets

from nucleo.aritmetica import exp_mod


def _criba(limite: int) -> list[int]:
    """Criba de Eratostenes: todos los primos menores que 'limite'."""
    es_primo_flag = [True] * limite
    es_primo_flag[0] = es_primo_flag[1] = False
    for i in range(2, int(limite ** 0.5) + 1):
        if es_primo_flag[i]:
            for multiplo in range(i * i, limite, i):
                es_primo_flag[multiplo] = False
    return [i for i, flag in enumerate(es_primo_flag) if flag]


# Primos menores a 2000: sirven para descartar rapido la mayoria de los
# compuestos antes de pagar el costo de Miller-Rabin.
PRIMOS_PEQUENOS = _criba(2000)


def _descomponer(n: int) -> tuple[int, int]:
    """Escribe n - 1 como 2^s * d con d impar. Devuelve (d, s)."""
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return d, s


def _es_testigo(a: int, n: int, d: int, s: int) -> bool:
    """True si la base 'a' demuestra que n es compuesto."""
    x = exp_mod(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def es_primo(n: int, rondas: int = 40) -> bool:
    """Indica si n es (probablemente) primo.

    Paso 1: division de prueba por primos pequenos (barato).
    Paso 2: 'rondas' pruebas de Miller-Rabin con bases aleatorias
            obtenidas de un generador criptograficamente seguro.
    """
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, s = _descomponer(n)
    for _ in range(rondas):
        a = 2 + secrets.randbelow(n - 3)       # base aleatoria en [2, n-2]
        if _es_testigo(a, n, d, s):
            return False
    return True
