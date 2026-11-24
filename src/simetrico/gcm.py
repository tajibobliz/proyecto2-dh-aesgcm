"""Modo GCM (Galois/Counter Mode) implementado a mano, NIST SP 800-38D.

GCM convierte un cifrador de bloque (AES) en un esquema AEAD: cifra y
autentica a la vez. Tiene dos partes:

1. Confidencialidad, modo contador (CTR):
       J0 = nonce (96 bits) || 0x00000001
       C_i = P_i xor AES_K(J0 + i)            i = 1, 2, 3...
   AES nunca cifra el mensaje directamente: genera un flujo de claves
   que se combina con XOR. Por eso descifrar es la misma operacion.

2. Autenticidad, GHASH en el cuerpo finito GF(2^128):
       H = AES_K(0^128)                        clave de autenticacion
       S = GHASH_H(A || C || longitudes)       polinomio evaluado en H
       etiqueta = S xor AES_K(J0)
   GHASH evalua un polinomio cuyos coeficientes son los bloques de los
   datos asociados (A) y del cifrado (C). Cambiar cualquier bit cambia el
   polinomio, y sin conocer H el atacante no puede calcular la etiqueta
   correcta. La probabilidad de falsificarla es del orden de 2^-128.

Por que el nonce no debe repetirse con la misma clave:
- se reutilizaria el flujo de claves: C1 xor C2 = P1 xor P2, y
- se podria despejar H y falsificar etiquetas a voluntad.
"""

from hashing.hmac_hkdf import comparar_constante
from simetrico.aes import AES256, TAM_BLOQUE

TAM_NONCE = 12
TAM_ETIQUETA = 16

# Polinomio de reduccion de GF(2^128): x^128 + x^7 + x^2 + x + 1.
# GCM numera los bits "al reves" (el bit mas significativo es x^0), por
# eso la constante de reduccion queda en el extremo alto: 0xE1 << 120.
_R = 0xE1 << 120


class EtiquetaInvalida(Exception):
    """La etiqueta no coincide: los datos fueron alterados."""


def gf128_mult(x: int, y: int) -> int:
    """Producto de dos elementos de GF(2^128) (Algoritmo 1 de SP 800-38D).

    Igual que en GF(2^8), pero con 128 bits: se recorre x bit a bit; si el
    bit vale 1 se acumula v; luego v se multiplica por el polinomio x
    (desplazamiento) y se reduce si sobrepasa el grado 127.
    """
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _rellenar(datos: bytes) -> bytes:
    """Completa con ceros hasta un multiplo de 16 bytes."""
    return datos + bytes(-len(datos) % TAM_BLOQUE)


def ghash(h: int, asociado: bytes, cifrado: bytes) -> int:
    """GHASH_H(A || C || len(A) || len(C)), por el metodo de Horner:
    Y = (Y xor X_i) * H para cada bloque X_i."""
    datos = (_rellenar(asociado) + _rellenar(cifrado)
             + (8 * len(asociado)).to_bytes(8, "big")
             + (8 * len(cifrado)).to_bytes(8, "big"))
    y = 0
    for i in range(0, len(datos), TAM_BLOQUE):
        y = gf128_mult(y ^ int.from_bytes(datos[i:i + TAM_BLOQUE], "big"), h)
    return y


class AESGCMPropio:
    """AES-256-GCM. Misma interfaz que AESGCM de la libreria cryptography:
    encrypt() devuelve cifrado || etiqueta, decrypt() la verifica."""

    def __init__(self, clave: bytes) -> None:
        self._aes = AES256(clave)
        self._h = int.from_bytes(self._aes.cifrar_bloque(bytes(TAM_BLOQUE)), "big")

    def _contador(self, nonce: bytes) -> bytes:
        if len(nonce) != TAM_NONCE:
            raise ValueError("El nonce debe tener 12 bytes (96 bits)")
        return nonce + b"\x00\x00\x00\x01"                     # J0

    def _ctr(self, j0: bytes, datos: bytes) -> bytes:
        """Modo contador: XOR con AES_K(J0 + 1), AES_K(J0 + 2), ..."""
        prefijo, contador = j0[:12], int.from_bytes(j0[12:], "big")
        salida = bytearray()
        for i in range(0, len(datos), TAM_BLOQUE):
            contador = (contador + 1) & 0xFFFFFFFF            # inc32
            flujo = self._aes.cifrar_bloque(prefijo + contador.to_bytes(4, "big"))
            trozo = datos[i:i + TAM_BLOQUE]
            salida += bytes(a ^ b for a, b in zip(trozo, flujo))
        return bytes(salida)

    def _etiqueta(self, j0: bytes, asociado: bytes, cifrado: bytes) -> bytes:
        s = ghash(self._h, asociado, cifrado)
        mascara = int.from_bytes(self._aes.cifrar_bloque(j0), "big")
        return (s ^ mascara).to_bytes(TAM_ETIQUETA, "big")

    def encrypt(self, nonce: bytes, datos: bytes, asociado: bytes | None) -> bytes:
        asociado = asociado or b""
        j0 = self._contador(nonce)
        cifrado = self._ctr(j0, datos)
        return cifrado + self._etiqueta(j0, asociado, cifrado)

    def decrypt(self, nonce: bytes, datos: bytes, asociado: bytes | None) -> bytes:
        asociado = asociado or b""
        if len(datos) < TAM_ETIQUETA:
            raise EtiquetaInvalida("Datos demasiado cortos")
        j0 = self._contador(nonce)
        cifrado, etiqueta = datos[:-TAM_ETIQUETA], datos[-TAM_ETIQUETA:]
        # Primero se verifica, y solo si es valida se descifra.
        if not comparar_constante(self._etiqueta(j0, asociado, cifrado), etiqueta):
            raise EtiquetaInvalida("Etiqueta de autenticacion invalida")
        return self._ctr(j0, cifrado)

    def borrar(self) -> None:
        """Borra las subclaves de AES y la clave de autenticacion H."""
        self._aes.borrar()
        self._h = 0
