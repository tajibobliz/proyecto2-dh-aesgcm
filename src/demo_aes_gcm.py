"""Demostracion del AES-256-GCM implementado a mano (sin librerias).

Uso (desde la raiz del proyecto):
    python src/demo_aes_gcm.py
"""

import secrets
import time

from simetrico.aes import AES256, CAJA_S, gf_mult
from simetrico.gcm import AESGCMPropio, EtiquetaInvalida


def main() -> None:
    print("=== 1. Aritmetica en GF(2^8) y caja S calculada ===")
    print(f"  {{57}} x {{83}} = {{{gf_mult(0x57, 0x83):02x}}}   (FIPS 197 espera c1)")
    print(f"  S(00) = {CAJA_S[0x00]:02x}   S(53) = {CAJA_S[0x53]:02x}   (estandar: 63 y ed)")

    print("\n=== 2. AES-256: vector oficial FIPS 197, apendice C.3 ===")
    clave = bytes(range(32))
    claro = bytes.fromhex("00112233445566778899aabbccddeeff")
    cifrado = AES256(clave).cifrar_bloque(claro).hex()
    esperado = "8ea2b7ca516745bfeafc49904b496089"
    print(f"  clave   : {clave.hex()}")
    print(f"  claro   : {claro.hex()}")
    print(f"  cifrado : {cifrado}")
    print(f"  coincide con el estandar: {cifrado == esperado}")

    print("\n=== 3. AES-256-GCM: vector oficial NIST, caso 14 ===")
    salida = AESGCMPropio(bytes(32)).encrypt(bytes(12), bytes(16), None)
    print(f"  cifrado  : {salida[:16].hex()}")
    print(f"  etiqueta : {salida[16:].hex()}")
    print(f"  coincide con el estandar: "
          f"{salida.hex() == 'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919'}")

    print("\n=== 4. Cifrado autenticado: deteccion de alteraciones ===")
    gcm = AESGCMPropio(secrets.token_bytes(32))
    nonce = secrets.token_bytes(12)
    paquete = gcm.encrypt(nonce, b"transferir 100 Bs", b"cabecera")
    print(f"  mensaje cifrado + etiqueta: {paquete.hex()}")
    print(f"  descifrado original       : {gcm.decrypt(nonce, paquete, b'cabecera')!r}")
    alterado = bytearray(paquete)
    alterado[0] ^= 0x01
    try:
        gcm.decrypt(nonce, bytes(alterado), b"cabecera")
        print("  mensaje alterado          : ACEPTADO (error)")
    except EtiquetaInvalida:
        print("  mensaje alterado (1 bit)  : RECHAZADO, etiqueta invalida")

    print("\n=== 5. Por que el nonce no se repite ===")
    p1, p2 = b"mensaje publico!", b"clave: 98765432"
    c1 = gcm.encrypt(bytes(12), p1, None)[:16]
    c2 = gcm.encrypt(bytes(12), p2, None)[:15]
    recuperado = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))
    print(f"  mismo nonce dos veces -> C1 xor C2 xor P1 = {recuperado!r}")
    print("  El atacante recupero el segundo mensaje sin conocer la clave.")

    print("\n=== 6. Rendimiento ===")
    datos = secrets.token_bytes(50_000)
    inicio = time.perf_counter()
    gcm.encrypt(secrets.token_bytes(12), datos, None)
    duracion = time.perf_counter() - inicio
    print(f"  AES-256-GCM propio (Python puro): {len(datos) / duracion / 1e3:.0f} kB/s")
    print("  Suficiente para mensajes de chat; la comparacion con la libreria")
    print("  esta en src/medir_rendimiento.py")


if __name__ == "__main__":
    main()
