"""Envio y recepcion de mensajes JSON por un socket TCP.

TCP entrega un flujo continuo de bytes, sin separar mensajes. Para saber
donde termina cada uno se antepone su longitud en 4 bytes (enmarcado por
longitud).

Este es el "canal inseguro" del enunciado: todo lo que pasa por aqui
puede ser leido o modificado por un tercero. La seguridad no depende del
transporte, sino de la criptografia que va encima.
"""

import json
import socket

from protocolo.errores import ErrorProtocolo

TAM_MAXIMO = 1 << 20          # 1 MiB: limite para no agotar la memoria


def enviar(conexion: socket.socket, mensaje: dict) -> None:
    datos = json.dumps(mensaje).encode("utf-8")
    conexion.sendall(len(datos).to_bytes(4, "big") + datos)


def _recibir_exacto(conexion: socket.socket, cantidad: int) -> bytes | None:
    """Lee exactamente 'cantidad' bytes. None si la conexion se cerro."""
    datos = b""
    while len(datos) < cantidad:
        trozo = conexion.recv(cantidad - len(datos))
        if not trozo:
            return None
        datos += trozo
    return datos


def recibir(conexion: socket.socket) -> dict | None:
    """Devuelve el siguiente mensaje, o None si la otra parte cerro."""
    cabecera = _recibir_exacto(conexion, 4)
    if cabecera is None:
        return None
    longitud = int.from_bytes(cabecera, "big")
    if longitud > TAM_MAXIMO:
        raise ErrorProtocolo("Mensaje demasiado grande")
    datos = _recibir_exacto(conexion, longitud)
    if datos is None:
        return None
    try:
        mensaje = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ErrorProtocolo("Mensaje que no es JSON valido") from None
    if not isinstance(mensaje, dict):
        raise ErrorProtocolo("Mensaje con formato invalido")
    return mensaje


def recibir_obligatorio(conexion: socket.socket) -> dict:
    mensaje = recibir(conexion)
    if mensaje is None:
        raise ErrorProtocolo("La otra parte cerro la conexion")
    return mensaje


def enviar_error(conexion: socket.socket, motivo: str) -> None:
    """Avisa a la otra parte que se aborta. Se ignora si ya no hay conexion."""
    try:
        enviar(conexion, {"tipo": "error", "motivo": motivo})
    except OSError:
        pass
