"""Demostracion de la Fase 2: SHA-256, HMAC y HKDF propios.

Uso (desde la raiz del proyecto):
    python src/demo_fase2.py
"""

import secrets
import time

from hashing.hmac_hkdf import hkdf, hmac_sha256, verificar_hmac
from hashing.sha256 import sha256


def main() -> None:
    print("=== 1. SHA-256 propio vs vectores oficiales del NIST ===")
    vectores = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]
    for texto, esperado in vectores:
        propio = sha256(texto).hex()
        etiqueta = repr(texto.decode()) if len(texto) < 20 else "'abcdbcde...nopq' (448 bits)"
        print(f"  {etiqueta:<30} {propio[:32]}...  coincide: {propio == esperado}")

    print("\n=== 2. Efecto avalancha ===")
    a, b = b"Diffie-Hellman", b"Diffie-Hellmao"
    ha, hb = sha256(a), sha256(b)
    distintos = bin(int.from_bytes(ha, "big") ^ int.from_bytes(hb, "big")).count("1")
    print(f"  {a.decode()} -> {ha.hex()[:40]}...")
    print(f"  {b.decode()} -> {hb.hex()[:40]}...")
    print(f"  Cambio de 1 letra: {distintos} de 256 bits distintos "
          f"({distintos / 256:.0%})")

    print("\n=== 3. HMAC-SHA256: deteccion de alteraciones ===")
    clave = secrets.token_bytes(32)
    mensaje = b"transferir 100 Bs a la cuenta 12345"
    etiqueta = hmac_sha256(clave, mensaje)
    alterado = b"transferir 900 Bs a la cuenta 12345"
    print(f"  etiqueta            : {etiqueta.hex()[:40]}...")
    print(f"  mensaje original    : {verificar_hmac(clave, mensaje, etiqueta)}")
    print(f"  mensaje alterado    : {verificar_hmac(clave, alterado, etiqueta)}")

    print("\n=== 4. HKDF: derivacion de claves ===")
    secreto = secrets.token_bytes(64)          # simula el secreto de DH
    k1 = hkdf(secreto, info=b"cliente->servidor")
    k2 = hkdf(secreto, info=b"servidor->cliente")
    print(f"  clave c->s (256 bits): {k1.hex()[:40]}...")
    print(f"  clave s->c (256 bits): {k2.hex()[:40]}...")
    print(f"  mismo secreto, claves distintas: {k1 != k2}")

    print("\n=== 5. Rendimiento ===")
    datos = secrets.token_bytes(200_000)
    inicio = time.perf_counter()
    sha256(datos)
    t_propio = time.perf_counter() - inicio
    print(f"  SHA-256 propio (Python puro): {len(datos) / t_propio / 1e6:.2f} MB/s")
    print("  La comparacion con la libreria esta en src/medir_rendimiento.py")


if __name__ == "__main__":
    main()
