"""HMAC-SHA256 (RFC 2104) y HKDF (RFC 5869), sobre el SHA-256 propio.

HMAC: codigo de autenticacion de mensajes.
    Un hash solo no autentica: cualquiera puede recalcularlo. HMAC mezcla
    una clave secreta con el mensaje, asi solo quien conoce la clave puede
    generar o verificar la etiqueta. Garantiza integridad y autenticidad.

        HMAC(K, m) = H( (K xor opad) || H( (K xor ipad) || m ) )

    Se usan dos pasadas de hash (interna y externa) para evitar el ataque
    de extension de longitud que sufre la construccion ingenua H(K || m).

HKDF: funcion de derivacion de claves.
    El secreto de Diffie-Hellman es un numero con estructura matematica,
    no bytes uniformes, asi que no debe usarse directo como clave AES.
    HKDF lo convierte en claves seguras en dos pasos:

        Extract: PRK = HMAC(sal, secreto)       concentra la entropia
        Expand:  OKM = T(1) || T(2) || ...      la estira al largo pedido
                 T(i) = HMAC(PRK, T(i-1) || info || i)
"""

from hashing.sha256 import TAM_BLOQUE, TAM_RESUMEN, sha256

_IPAD = bytes([0x36] * TAM_BLOQUE)
_OPAD = bytes([0x5C] * TAM_BLOQUE)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def hmac_sha256(clave: bytes, mensaje: bytes) -> bytes:
    """Etiqueta HMAC-SHA256 (32 bytes) de 'mensaje' con 'clave'."""
    if len(clave) > TAM_BLOQUE:           # claves largas se resumen primero
        clave = sha256(clave)
    clave = clave.ljust(TAM_BLOQUE, b"\x00")

    interno = sha256(_xor(clave, _IPAD) + mensaje)
    return sha256(_xor(clave, _OPAD) + interno)


def comparar_constante(a: bytes, b: bytes) -> bool:
    """Compara dos cadenas de bytes sin cortar en la primera diferencia.

    Un '==' normal termina antes cuanto antes difieren los bytes, y ese
    tiempo le permitiria a un atacante adivinar una etiqueta byte a byte
    (ataque de temporizacion). Aqui siempre se recorren todos los bytes.
    """
    if len(a) != len(b):
        return False
    diferencia = 0
    for x, y in zip(a, b):
        diferencia |= x ^ y
    return diferencia == 0


def verificar_hmac(clave: bytes, mensaje: bytes, etiqueta: bytes) -> bool:
    """True si 'etiqueta' es el HMAC correcto de 'mensaje'."""
    return comparar_constante(hmac_sha256(clave, mensaje), etiqueta)


def hkdf_extract(sal: bytes, material: bytes) -> bytes:
    """Paso Extract: devuelve la clave pseudoaleatoria PRK (32 bytes)."""
    if not sal:
        sal = bytes(TAM_RESUMEN)          # sal por defecto: 32 bytes en cero
    return hmac_sha256(sal, material)


def hkdf_expand(prk: bytes, info: bytes, longitud: int) -> bytes:
    """Paso Expand: genera 'longitud' bytes de clave a partir de PRK."""
    if not 0 < longitud <= 255 * TAM_RESUMEN:
        raise ValueError("Longitud fuera de rango (1 a 8160 bytes)")
    salida = b""
    bloque = b""
    contador = 1
    while len(salida) < longitud:
        bloque = hmac_sha256(prk, bloque + info + bytes([contador]))
        salida += bloque
        contador += 1
    return salida[:longitud]


def hkdf(material: bytes, sal: bytes = b"", info: bytes = b"",
         longitud: int = 32) -> bytes:
    """HKDF completo (Extract + Expand). Por defecto 32 bytes: AES-256.

    'info' liga la clave a un uso concreto: con el mismo secreto, info
    distintos producen claves independientes (separacion de dominios).
    """
    return hkdf_expand(hkdf_extract(sal, material), info, longitud)
