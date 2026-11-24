"""Excepciones del protocolo.

Principio Zero-Trust: ante cualquier dato invalido se aborta con un error
explicito; nunca se continua "por las dudas" con valores no verificados.
"""


class ErrorProtocolo(Exception):
    """Un mensaje o parametro recibido no supero las verificaciones."""


class ErrorCanal(ErrorProtocolo):
    """Un mensaje cifrado fue alterado, repetido o reordenado."""
