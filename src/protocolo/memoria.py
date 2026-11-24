"""Gestion segura de memoria.

Una clave que queda en memoria despues de usarse puede terminar en un
volcado de memoria, en el archivo de intercambio (swap) o al alcance de
otro proceso. La practica correcta es sobrescribirla apenas deja de
necesitarse.

En Python esto solo es posible con objetos mutables: por eso las claves
se guardan en 'bytearray' y no en 'bytes' (que es inmutable y no se
puede borrar).

Limitaciones honestas de Python, documentadas en el informe:
- Los enteros (como el exponente privado de Diffie-Hellman) son
  inmutables: solo se puede soltar la referencia y esperar al recolector
  de basura.
- Las librerias pueden conservar copias internas de la clave.
Un lenguaje como C o Rust permite un control total de este aspecto.
"""


def borrar(buffer: bytearray) -> None:
    """Sobrescribe con ceros el contenido de un bytearray."""
    for i in range(len(buffer)):
        buffer[i] = 0
