"""Generacion de primos y del grupo para Diffie-Hellman.

Diffie-Hellman trabaja en el grupo multiplicativo de los enteros modulo
un primo p. Para que sea seguro no sirve cualquier primo: se usa un
"primo seguro", es decir p = 2q + 1 donde q tambien es primo.

Por que: el orden del grupo es p - 1 = 2q. Si p - 1 tuviera muchos
factores pequenos, el logaritmo discreto se resolveria rapido con el
ataque de Pohlig-Hellman. Con p = 2q + 1 los unicos subgrupos tienen
orden 1, 2, q y 2q, y trabajamos en el de orden primo q.

El generador g se elige dentro de ese subgrupo de orden q. Asi los
valores publicos no filtran ningun bit del exponente secreto y se evitan
los ataques de confinamiento a subgrupos pequenos.
"""

import secrets
from dataclasses import dataclass

from nucleo.aritmetica import exp_mod
from nucleo.primalidad import PRIMOS_PEQUENOS, es_primo


@dataclass(frozen=True)
class GrupoDH:
    """Parametros publicos del grupo: primo p, orden q y generador g."""

    p: int
    q: int
    g: int

    @property
    def bits(self) -> int:
        return self.p.bit_length()


def _candidato_impar(bits: int) -> int:
    """Entero aleatorio impar de exactamente 'bits' bits."""
    n = secrets.randbits(bits)
    n |= 1 << (bits - 1)        # fuerza el bit mas alto: tamano exacto
    n |= 1                      # fuerza el bit mas bajo: impar
    return n


def generar_primo(bits: int, rondas: int = 40) -> int:
    """Genera un primo aleatorio de 'bits' bits."""
    if bits < 16:
        raise ValueError("Se requieren al menos 16 bits")
    while True:
        candidato = _candidato_impar(bits)
        if es_primo(candidato, rondas):
            return candidato


def generar_primo_seguro(bits: int, rondas: int = 40) -> tuple[int, int]:
    """Genera un primo seguro p = 2q + 1 de 'bits' bits. Devuelve (p, q).

    Los primos seguros son escasos, asi que se filtra en tres niveles,
    del mas barato al mas caro:

    1. Division de prueba de q y de p a la vez por primos pequenos.
    2. Una sola ronda de Miller-Rabin sobre q (descarta casi todo).
    3. Prueba completa de q y de p.
    """
    if bits < 32:
        raise ValueError("Se requieren al menos 32 bits")
    while True:
        q = _candidato_impar(bits - 1)
        p = 2 * q + 1

        if any(q % r == 0 or p % r == 0 for r in PRIMOS_PEQUENOS):
            continue
        if not es_primo(q, rondas=1):
            continue
        if es_primo(p, rondas) and es_primo(q, rondas):
            return p, q


def encontrar_generador(p: int, q: int) -> int:
    """Encuentra un generador g del subgrupo de orden q de Z_p*.

    Truco: para p = 2q + 1, elevar al cuadrado cualquier h manda el
    resultado al subgrupo de orden q (los residuos cuadraticos). Si
    g = h^2 mod p no es 1, entonces su orden es exactamente q, porque
    q es primo y el orden debe dividir a q.
    """
    while True:
        h = 2 + secrets.randbelow(p - 3)       # h en [2, p-2]
        g = exp_mod(h, 2, p)
        if g not in (1, p - 1) and exp_mod(g, q, p) == 1:
            return g


def validar_grupo(grupo: GrupoDH, rondas: int = 40) -> None:
    """Verifica que (p, q, g) sea un grupo valido. Lanza ValueError si no.

    Principio Zero-Trust: los parametros recibidos de la otra parte no se
    asumen correctos, se comprueban antes de usarlos.
    """
    p, q, g = grupo.p, grupo.q, grupo.g
    if p != 2 * q + 1:
        raise ValueError("p no tiene la forma 2q + 1")
    if not es_primo(q, rondas) or not es_primo(p, rondas):
        raise ValueError("p o q no son primos")
    if not 1 < g < p - 1:
        raise ValueError("g fuera del rango (1, p-1)")
    if exp_mod(g, q, p) != 1:
        raise ValueError("g no pertenece al subgrupo de orden q")


def generar_grupo(bits: int, rondas: int = 40) -> GrupoDH:
    """Genera un grupo Diffie-Hellman completo de 'bits' bits."""
    p, q = generar_primo_seguro(bits, rondas)
    g = encontrar_generador(p, q)
    return GrupoDH(p=p, q=q, g=g)
