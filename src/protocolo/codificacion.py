"""Conversion entre enteros, bytes y texto hexadecimal.

Antes de aplicar un hash o una firma sobre varios campos, estos deben
serializarse de forma inequivoca. Si solo se concatenaran, los campos
("ab", "c") y ("a", "bc") darian los mismos bytes y un atacante podria
mover datos de un campo a otro. Por eso cada campo va precedido de su
longitud.
"""

from protocolo.errores import ErrorProtocolo


def int_a_bytes(n: int, longitud: int) -> bytes:
    """Entero no negativo a bytes big-endian de longitud fija."""
    return n.to_bytes(longitud, "big")


def bytes_a_int(datos: bytes) -> int:
    return int.from_bytes(datos, "big")


def codificar(*campos: bytes) -> bytes:
    """Une varios campos anteponiendo a cada uno su longitud (4 bytes)."""
    return b"".join(len(c).to_bytes(4, "big") + c for c in campos)


def leer_entero(mensaje: dict, campo: str, max_hex: int = 1024) -> int:
    """Extrae un entero hexadecimal de un mensaje recibido, validandolo."""
    valor = mensaje.get(campo)
    if not isinstance(valor, str) or not 0 < len(valor) <= max_hex:
        raise ErrorProtocolo(f"Campo '{campo}' ausente o de tamano invalido")
    try:
        return int(valor, 16)
    except ValueError:
        raise ErrorProtocolo(f"Campo '{campo}' no es hexadecimal") from None


def leer_bytes(mensaje: dict, campo: str, max_bytes: int = 1 << 20) -> bytes:
    """Extrae bytes en hexadecimal de un mensaje recibido, validandolos."""
    valor = mensaje.get(campo)
    if not isinstance(valor, str) or len(valor) > 2 * max_bytes:
        raise ErrorProtocolo(f"Campo '{campo}' ausente o de tamano invalido")
    try:
        return bytes.fromhex(valor)
    except ValueError:
        raise ErrorProtocolo(f"Campo '{campo}' no es hexadecimal") from None
