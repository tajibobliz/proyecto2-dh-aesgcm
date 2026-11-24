"""Cliente: se conecta, ejecuta el handshake y envia mensajes cifrados."""

import argparse
import socket
import time
from pathlib import Path

from protocolo.canal_seguro import CanalSeguro
from protocolo.codificacion import leer_bytes
from protocolo.errores import ErrorProtocolo
from protocolo.handshake import SesionCliente
from protocolo.identidad import Identidad
from red.transporte import enviar, enviar_error, recibir_obligatorio


class ClienteSeguro:
    """Conexion segura con el servidor. Usar con 'with' para cerrarla."""

    def __init__(self, host: str, puerto: int, identidad: Identidad | None = None,
                 publica_servidor: int | None = None) -> None:
        self._sesion = SesionCliente(identidad, publica_servidor)
        self._conexion = socket.create_connection((host, puerto), timeout=30)
        self._canal: CanalSeguro | None = None
        self.huella = ""
        self.duracion_ms = 0.0

    def conectar(self) -> None:
        """Ejecuta el handshake. Lanza ErrorProtocolo si algo no verifica."""
        inicio = time.perf_counter()
        enviar(self._conexion, self._sesion.crear_hola())
        respuesta = recibir_obligatorio(self._conexion)
        try:
            confirmacion = self._sesion.procesar_respuesta(respuesta)
        except ErrorProtocolo as error:
            enviar_error(self._conexion, str(error))      # avisa y aborta
            raise
        enviar(self._conexion, confirmacion)
        self._sesion.procesar_listo(recibir_obligatorio(self._conexion))
        self._canal = self._sesion.canal()
        self.huella = self._sesion.claves.huella
        self.duracion_ms = (time.perf_counter() - inicio) * 1000

    def enviar_mensaje(self, texto: bytes) -> bytes:
        """Envia un mensaje cifrado y devuelve la respuesta descifrada."""
        if self._canal is None:
            raise ErrorProtocolo("Primero debe ejecutarse conectar()")
        paquete = self._canal.cifrar(texto)
        enviar(self._conexion, {"tipo": "datos", "carga": paquete.hex()})
        mensaje = recibir_obligatorio(self._conexion)
        if mensaje.get("tipo") == "error":
            raise ErrorProtocolo(f"El servidor aborto: {mensaje.get('motivo')}")
        if mensaje.get("tipo") != "datos":
            raise ErrorProtocolo("Se esperaba un mensaje de datos")
        return self._canal.descifrar(leer_bytes(mensaje, "carga"))

    def cerrar(self) -> None:
        if self._canal is not None:
            self._canal.cerrar()              # borra las claves de memoria
        self._conexion.close()

    def __enter__(self) -> "ClienteSeguro":
        return self

    def __exit__(self, *_) -> None:
        self.cerrar()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente del canal seguro DH + AES-256-GCM")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=5000)
    parser.add_argument("--claves", default="claves", help="carpeta de identidades")
    parser.add_argument("--anonimo", action="store_true",
                        help="sin autenticacion (SOLO demostracion MITM)")
    parser.add_argument("--mensaje", action="append",
                        help="mensaje a enviar (repetible). Sin esta opcion: modo interactivo")
    args = parser.parse_args()

    identidad = publica_servidor = None
    if not args.anonimo:
        carpeta = Path(args.claves)
        try:
            identidad = Identidad.cargar(carpeta / "cliente.json")
            servidor = Identidad.cargar(carpeta / "servidor.pub.json")
        except FileNotFoundError:
            raise SystemExit("No se encontraron las identidades. Ejecute primero:\n"
                             "    python src/generar_identidades.py")
        publica_servidor = servidor.publica
        print(f"Identidad del cliente  (huella): {identidad.huella()}")
        print(f"Servidor esperado      (huella): {servidor.huella()}")
    else:
        print("ADVERTENCIA: modo anonimo, no se verifica al servidor")

    try:
        cliente = ClienteSeguro(args.host, args.puerto, identidad, publica_servidor)
    except OSError as error:
        raise SystemExit(f"No se pudo conectar a {args.host}:{args.puerto}: {error}")

    with cliente:
        try:
            cliente.conectar()
            print(f"[=] Canal AES-256-GCM establecido en {cliente.duracion_ms:.0f} ms. "
                  f"Huella de sesion: {cliente.huella}")
            if args.mensaje:
                for texto in args.mensaje:
                    respuesta = cliente.enviar_mensaje(texto.encode("utf-8"))
                    print(f"    -> {texto!r}")
                    print(f"    <- {respuesta.decode('utf-8', 'replace')!r}")
            else:
                print("Escriba mensajes (linea vacia para salir).")
                while True:
                    texto = input("> ")
                    if not texto:
                        break
                    respuesta = cliente.enviar_mensaje(texto.encode("utf-8"))
                    print(f"< {respuesta.decode('utf-8', 'replace')}")
        except ErrorProtocolo as error:
            raise SystemExit(f"[!] SESION ABORTADA: {error}")
        except (EOFError, KeyboardInterrupt):
            print()
    print("Conexion cerrada y claves borradas de memoria.")


if __name__ == "__main__":
    main()
