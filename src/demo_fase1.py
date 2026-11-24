"""Demostracion de la Fase 1: nucleo matematico.

Uso (desde la raiz del proyecto):
    python src/demo_fase1.py            # grupos de 256 y 512 bits
    python src/demo_fase1.py 256 512 1024
"""

import sys
import time

from nucleo.aritmetica import exp_mod, inverso_mod
from nucleo.primalidad import es_primo
from nucleo.primos import generar_grupo, validar_grupo


def main() -> None:
    tamanos = [int(x) for x in sys.argv[1:]] or [256, 512]

    print("=== 1. Exponenciacion modular (square-and-multiply) ===")
    print(f"  7^560 mod 561        = {exp_mod(7, 560, 561)}")
    print(f"  propio == pow nativo : {exp_mod(7, 560, 561) == pow(7, 560, 561)}")

    print("\n=== 2. Inverso modular (Euclides extendido) ===")
    inv = inverso_mod(17, 3120)
    print(f"  17^-1 mod 3120       = {inv}")
    print(f"  comprobacion 17*inv  = {17 * inv % 3120} (mod 3120)")

    print("\n=== 3. Miller-Rabin ===")
    casos = [
        ("561", 561, "Carmichael: engana a Fermat"),
        ("1729", 1729, "Carmichael"),
        ("2^127 - 1", 2**127 - 1, "primo de Mersenne"),
        ("2^127 + 1", 2**127 + 1, "divisible por 3"),
    ]
    for etiqueta, n, nota in casos:
        veredicto = "primo" if es_primo(n) else "compuesto"
        print(f"  {etiqueta:<10} -> {veredicto:<9} ({nota})")

    print("\n=== 4. Generacion de grupo Diffie-Hellman (p = 2q + 1) ===")
    for bits in tamanos:
        inicio = time.perf_counter()
        grupo = generar_grupo(bits)
        duracion = time.perf_counter() - inicio
        validar_grupo(grupo)
        print(f"  {bits} bits: generado y validado en {duracion:.2f} s")
        print(f"    p = {hex(grupo.p)[:34]}...")
        print(f"    g = {hex(grupo.g)[:34]}...")


if __name__ == "__main__":
    main()
