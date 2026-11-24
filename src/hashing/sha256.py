"""SHA-256 implementado a mano segun el estandar FIPS 180-4.

Una funcion hash convierte un mensaje de cualquier tamano en un resumen
fijo de 256 bits. Propiedades que importan en este proyecto:

- Unidireccional: del resumen no se puede recuperar el mensaje.
- Resistente a colisiones: no es viable hallar dos mensajes con el
  mismo resumen.
- Efecto avalancha: cambiar un bit del mensaje cambia cerca de la mitad
  de los bits del resumen.

Estructura (construccion Merkle-Damgard):

1. Relleno: se agrega un bit 1, ceros, y la longitud del mensaje en
   64 bits, hasta completar un multiplo de 512 bits.
2. El mensaje se parte en bloques de 512 bits (64 bytes).
3. Cada bloque pasa por la funcion de compresion (64 rondas), que
   mezcla el bloque con el estado de 256 bits (8 palabras de 32 bits).
4. El estado final es el resumen.
"""

from math import isqrt

from nucleo.primalidad import PRIMOS_PEQUENOS

MASCARA = 0xFFFFFFFF          # todas las operaciones son modulo 2^32
TAM_BLOQUE = 64               # bytes por bloque
TAM_RESUMEN = 32              # bytes del resumen


def _raiz_cubica_entera(n: int) -> int:
    """Parte entera de la raiz cubica de n (busqueda binaria)."""
    bajo, alto = 0, 1 << ((n.bit_length() + 2) // 3 + 1)
    while bajo < alto:
        medio = (bajo + alto + 1) // 2
        if medio ** 3 <= n:
            bajo = medio
        else:
            alto = medio - 1
    return bajo


# Las constantes de SHA-256 no son arbitrarias ("nothing up my sleeve"):
# - H0: primeros 32 bits de la parte fraccionaria de la raiz cuadrada
#       de los primeros 8 primos.
# - K:  primeros 32 bits de la parte fraccionaria de la raiz cubica
#       de los primeros 64 primos.
# Se calculan aqui con aritmetica entera en vez de copiarlas de una tabla.
H0 = tuple(isqrt(p << 64) & MASCARA for p in PRIMOS_PEQUENOS[:8])
K = tuple(_raiz_cubica_entera(p << 96) & MASCARA for p in PRIMOS_PEQUENOS[:64])


def _rotar_der(x: int, n: int) -> int:
    """Rotacion circular a la derecha de una palabra de 32 bits."""
    return ((x >> n) | (x << (32 - n))) & MASCARA


def _comprimir(estado: list[int], bloque: bytes) -> list[int]:
    """Funcion de compresion: mezcla un bloque de 64 bytes con el estado."""
    # 1. Expansion: las 16 palabras del bloque se extienden a 64.
    w = [int.from_bytes(bloque[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        s0 = _rotar_der(w[t - 15], 7) ^ _rotar_der(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotar_der(w[t - 2], 17) ^ _rotar_der(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & MASCARA)

    # 2. 64 rondas sobre las variables de trabajo a..h.
    a, b, c, d, e, f, g, h = estado
    for t in range(64):
        sigma1 = _rotar_der(e, 6) ^ _rotar_der(e, 11) ^ _rotar_der(e, 25)
        eleccion = (e & f) ^ (~e & MASCARA & g)            # Ch: e elige f o g
        t1 = (h + sigma1 + eleccion + K[t] + w[t]) & MASCARA
        sigma0 = _rotar_der(a, 2) ^ _rotar_der(a, 13) ^ _rotar_der(a, 22)
        mayoria = (a & b) ^ (a & c) ^ (b & c)              # Maj: bit mayoritario
        t2 = (sigma0 + mayoria) & MASCARA
        h, g, f, e = g, f, e, (d + t1) & MASCARA
        d, c, b, a = c, b, a, (t1 + t2) & MASCARA

    # 3. Se suma el resultado al estado anterior (Davies-Meyer).
    return [(x + y) & MASCARA for x, y in zip(estado, (a, b, c, d, e, f, g, h))]


class SHA256:
    """Calculo incremental: permite alimentar el mensaje por partes."""

    def __init__(self, datos: bytes = b"") -> None:
        self._estado = list(H0)
        self._pendiente = b""         # bytes que aun no completan un bloque
        self._longitud = 0            # bytes totales recibidos
        if datos:
            self.update(datos)

    def update(self, datos: bytes) -> "SHA256":
        self._longitud += len(datos)
        buffer = self._pendiente + bytes(datos)
        completos = len(buffer) // TAM_BLOQUE * TAM_BLOQUE
        for i in range(0, completos, TAM_BLOQUE):
            self._estado = _comprimir(self._estado, buffer[i:i + TAM_BLOQUE])
        self._pendiente = buffer[completos:]
        return self

    def digest(self) -> bytes:
        # Relleno: 0x80, ceros, y la longitud en bits como entero de 64 bits.
        ceros = (55 - self._longitud) % TAM_BLOQUE
        relleno = b"\x80" + b"\x00" * ceros + (self._longitud * 8).to_bytes(8, "big")
        final = self._pendiente + relleno

        estado = self._estado                 # no se modifica el objeto
        for i in range(0, len(final), TAM_BLOQUE):
            estado = _comprimir(estado, final[i:i + TAM_BLOQUE])
        return b"".join(palabra.to_bytes(4, "big") for palabra in estado)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(datos: bytes) -> bytes:
    """Resumen SHA-256 (32 bytes) de 'datos'."""
    return SHA256(datos).digest()
