"""Servidor: acepta conexiones, ejecuta el handshake y responde mensajes
cifrados con AES-256-GCM."""

import argparse
import socket
import time
from pathlib import Path

from protocolo.codificacion import leer_bytes
from protocolo.canal_seguro import IMPLEMENTACIONES
from protocolo.errores import ErrorProtocolo
from protocolo.handshake import SesionServidor
from protocolo.identidad import Identidad
from red.transporte import enviar, enviar_error, recibir, recibir_obligatorio


def _corto(valor_hex: str) -> str:
    return valor_hex[:24] + "..." if len(valor_hex) > 24 else valor_hex


class ServidorSeguro:
    def __init__(self, host: str, puerto: int, identidad: Identidad | None,
                 publicas_autorizadas: tuple[int, ...] = (),
                 permitir_anonimo: bool = False, silencioso: bool = False,
                 aes: str = "propia") -> None:
        self._identidad = identidad
        self._aes = aes
        self._autorizadas = publicas_autorizadas
        self._permitir_anonimo = permitir_anonimo
        self._silencioso = silencioso
        self.recibidos: list[bytes] = []          # textos descifrados
        self.errores: list[str] = []              # ataques detectados
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, puerto))
        self._socket.listen(5)
        self.puerto = self._socket.getsockname()[1]

    def _log(self, texto: str) -> None:
        if not self._silencioso:
            print(texto, flush=True)

    def atender_una(self) -> None:
        """Espera una conexion y la atiende hasta que se cierre."""
        conexion, direccion = self._socket.accept()
        self._log(f"\n[+] Conexion desde {direccion[0]}:{direccion[1]}")
        with conexion:
            try:
                self._atender(conexion)
            except ErrorProtocolo as error:
                self.errores.append(str(error))
                self._log(f"[!] SESION ABORTADA: {error}")
                enviar_error(conexion, str(error))
            except OSError as error:
                self._log(f"[!] Error de red: {error}")
        self._log("[-] Conexion cerrada")

    def _atender(self, conexion: socket.socket) -> None:
        sesion = SesionServidor(self._identidad, self._autorizadas,
                                self._permitir_anonimo)
        inicio = time.perf_counter()

        hola = recibir_obligatorio(conexion)
        self._log(f"    <- hola          modo={hola.get('modo')} "
                  f"grupo={hola.get('grupo')} A={_corto(str(hola.get('A')))}")
        respuesta = sesion.procesar_hola(hola)
        enviar(conexion, respuesta)
        self._log(f"    -> respuesta     B={_corto(respuesta['B'])} "
                  f"firma={'si' if 'firma' in respuesta else 'no'}")

        confirmacion = recibir_obligatorio(conexion)
        listo = sesion.procesar_confirmacion(confirmacion)
        enviar(conexion, listo)
        duracion = (time.perf_counter() - inicio) * 1000
        self._log(f"    <- confirmacion  firma del cliente verificada"
                  if sesion.modo == "autenticado" else
                  "    <- confirmacion  (modo anonimo: sin verificar identidad)")
        self._log(f"[=] Canal AES-256-GCM ({self._aes}) establecido en {duracion:.0f} ms. "
                  f"Huella de sesion: {sesion.claves.huella}")

        with sesion.canal(self._aes) as canal:
            while True:
                mensaje = recibir(conexion)
                if mensaje is None:
                    break
                if mensaje.get("tipo") != "datos":
                    raise ErrorProtocolo("Se esperaba un mensaje de datos")
                paquete = leer_bytes(mensaje, "carga")
                claro = canal.descifrar(paquete)
                self.recibidos.append(claro)
                self._log(f"    <- cifrado  ({len(paquete)} bytes): {paquete.hex()[:48]}...")
                self._log(f"       descifrado y verificado: {claro.decode('utf-8', 'replace')!r}")
                eco = canal.cifrar(b"recibido: " + claro)
                enviar(conexion, {"tipo": "datos", "carga": eco.hex()})

    def cerrar(self) -> None:
        self._socket.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor del canal seguro DH + AES-256-GCM")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=5000)
    parser.add_argument("--claves", default="claves", help="carpeta de identidades")
    parser.add_argument("--aes", choices=IMPLEMENTACIONES, default="propia",
                        help="implementacion de AES-256-GCM (por defecto: propia)")
    parser.add_argument("--permitir-anonimo", action="store_true",
                        help="acepta clientes sin autenticar (SOLO demostracion MITM)")
    args = parser.parse_args()

    carpeta = Path(args.claves)
    try:
        identidad = Identidad.cargar(carpeta / "servidor.json")
        cliente = Identidad.cargar(carpeta / "cliente.pub.json")
    except FileNotFoundError:
        raise SystemExit("No se encontraron las identidades. Ejecute primero:\n"
                         "    python src/generar_identidades.py")

    servidor = ServidorSeguro(args.host, args.puerto, identidad,
                              (cliente.publica,), args.permitir_anonimo,
                              aes=args.aes)
    print(f"Servidor escuchando en {args.host}:{servidor.puerto}")
    print(f"Identidad del servidor (huella): {identidad.huella()}")
    print(f"Cliente autorizado     (huella): {cliente.huella()}")
    print(f"Implementacion AES-256-GCM     : {args.aes}")
    if args.permitir_anonimo:
        print("ADVERTENCIA: se aceptan clientes anonimos (vulnerable a MITM)")
    print("Ctrl+C para detener.")
    try:
        while True:
            servidor.atender_una()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        servidor.cerrar()


if __name__ == "__main__":
    main()
