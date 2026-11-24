"""Atacante en el medio del canal, para las demostraciones en vivo.

Se ubica entre el cliente y el servidor (el cliente se conecta al puerto
del atacante creyendo que es el servidor) y ejecuta uno de estos ataques:

- pasivo:  solo escucha. Ve p, g, A, B y los mensajes cifrados, pero no
           puede obtener la clave (problema del logaritmo discreto).
- alterar: cambia un bit de un mensaje cifrado. AES-GCM lo detecta por
           la etiqueta de autenticacion.
- repetir: reenvia un mensaje cifrado ya visto (replay). El numero de
           secuencia lo delata.
- mitm:    ataque activo Man-in-the-Middle. Sustituye A y B por su propio
           valor publico y negocia una clave con cada parte.
             * Modo anonimo:     el ataque TIENE EXITO, lee todo.
             * Modo autenticado: la firma digital lo DETECTA.

Uso exclusivamente academico, contra el servidor propio del proyecto.
"""

import argparse
import socket

from protocolo.canal_seguro import CanalSeguro
from protocolo.dh import ParClavesDH, calcular_secreto
from protocolo.errores import ErrorProtocolo
from protocolo.grupos import obtener_grupo
from protocolo.handshake import calcular_transcripcion, derivar_claves_sesion
from red.transporte import enviar, recibir

MODOS = ("pasivo", "alterar", "repetir", "mitm")


def _corto(valor: str, n: int = 32) -> str:
    return valor[:n] + "..." if len(valor) > n else valor


def _es_error(mensaje: dict | None) -> bool:
    return mensaje is not None and mensaje.get("tipo") == "error"


class Atacante:
    def __init__(self, host: str, puerto: int, destino_host: str,
                 destino_puerto: int, modo: str, silencioso: bool = False) -> None:
        if modo not in MODOS:
            raise ValueError(f"Modo desconocido: {modo}")
        self._destino = (destino_host, destino_puerto)
        self._modo = modo
        self._silencioso = silencioso
        self.observados: list[bytes] = []      # paquetes cifrados vistos
        self.capturados: list[bytes] = []      # textos en claro obtenidos
        self.resultado = ""                    # "exitoso", "detectado" o ""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, puerto))
        self._socket.listen(5)
        self.puerto = self._socket.getsockname()[1]

    def _log(self, texto: str) -> None:
        if not self._silencioso:
            print(texto, flush=True)

    def atender_una(self) -> None:
        cliente, direccion = self._socket.accept()
        self._log(f"\n[+] Victima conectada desde {direccion[0]}:{direccion[1]}")
        try:
            servidor = socket.create_connection(self._destino, timeout=30)
        except OSError as error:
            self._log(f"[!] No se pudo conectar al servidor real: {error}")
            cliente.close()
            return
        with cliente, servidor:
            try:
                if self._modo == "mitm":
                    self._ataque_mitm(cliente, servidor)
                else:
                    self._ataque_sobre_el_canal(cliente, servidor)
            except (ErrorProtocolo, OSError, ValueError, KeyError) as error:
                self._log(f"[!] Ataque interrumpido: {error}")
        self._log("[-] Conexiones cerradas")

    # ------------------------------------------------------------------
    # Ataques que no tocan el handshake: pasivo, alterar, repetir
    # ------------------------------------------------------------------
    def _ataque_sobre_el_canal(self, cliente, servidor) -> None:
        hola = recibir(cliente)
        if hola is None:
            return
        enviar(servidor, hola)
        respuesta = recibir(servidor)
        if respuesta is None:
            return
        enviar(cliente, respuesta)
        self._log("[*] Handshake observado. El atacante conoce los valores publicos:")
        self._log(f"      grupo = {hola.get('grupo')}  (p y g son publicos)")
        self._log(f"      A = g^a mod p = {_corto(str(hola.get('A')))}")
        self._log(f"      B = g^b mod p = {_corto(str(respuesta.get('B')))}")
        self._log("    Para obtener la clave necesitaria 'a' o 'b': logaritmo discreto.")
        for origen, destino in ((cliente, servidor), (servidor, cliente)):
            mensaje = recibir(origen)             # confirmacion y listo
            if mensaje is None:
                return
            enviar(destino, mensaje)

        ataque_hecho = False
        while True:
            mensaje = recibir(cliente)
            if mensaje is None:
                break
            original = dict(mensaje)
            if mensaje.get("tipo") == "datos":
                carga = bytes.fromhex(mensaje["carga"])
                self.observados.append(carga)
                self._log(f"[*] Mensaje cifrado interceptado ({len(carga)} bytes): "
                          f"{_corto(carga.hex(), 56)}")
                self._log("    Contenido ilegible sin la clave.")
                if self._modo == "alterar" and not ataque_hecho:
                    alterada = bytearray(carga)
                    alterada[8] ^= 0x01               # primer byte del cifrado
                    mensaje["carga"] = bytes(alterada).hex()
                    ataque_hecho = True
                    self._log("[>] ATAQUE: se altera 1 bit del mensaje cifrado y se reenvia")

            enviar(servidor, mensaje)
            respuesta = recibir(servidor)
            if respuesta is None:
                break
            enviar(cliente, respuesta)
            if _es_error(respuesta):
                self.resultado = "detectado"
                self._log(f"[x] ATAQUE DETECTADO por el servidor: {respuesta.get('motivo')}")
                break

            if self._modo == "repetir" and not ataque_hecho:
                ataque_hecho = True
                self._log("[>] ATAQUE: se reenvia el mismo mensaje cifrado (replay)")
                enviar(servidor, original)
                segunda = recibir(servidor)
                if _es_error(segunda):
                    self.resultado = "detectado"
                    self._log(f"[x] ATAQUE DETECTADO por el servidor: {segunda.get('motivo')}")
                else:
                    self.resultado = "exitoso"
                    self._log("[!] El servidor acepto el mensaje repetido")
                break

        if self._modo == "pasivo":
            self._log(f"[=] Escucha finalizada: {len(self.observados)} mensajes cifrados "
                      f"vistos, 0 descifrados.")

    # ------------------------------------------------------------------
    # Ataque activo Man-in-the-Middle sobre el handshake
    # ------------------------------------------------------------------
    def _ataque_mitm(self, cliente, servidor) -> None:
        hola = recibir(cliente)
        if hola is None:
            return
        nombre_grupo = hola["grupo"]
        modo = hola["modo"]
        grupo = obtener_grupo(nombre_grupo)
        eva = ParClavesDH.generar(grupo)
        E = format(eva.publica, "x")
        self._log(f"[*] Handshake interceptado (modo {modo}).")
        self._log(f"[>] ATAQUE: se sustituye A y B por el valor propio E = {_corto(E)}")

        enviar(servidor, dict(hola, A=E))
        respuesta = recibir(servidor)
        if respuesta is None or _es_error(respuesta):
            self.resultado = "detectado"
            motivo = respuesta.get("motivo") if respuesta else "conexion cerrada"
            self._log(f"[x] ATAQUE DETECTADO por el servidor: {motivo}")
            if respuesta:
                enviar(cliente, respuesta)
            return
        enviar(cliente, dict(respuesta, B=E))         # la firma se reenvia tal cual

        confirmacion = recibir(cliente)
        if confirmacion is None or _es_error(confirmacion):
            self.resultado = "detectado"
            motivo = confirmacion.get("motivo") if confirmacion else "conexion cerrada"
            self._log(f"[x] ATAQUE DETECTADO por el cliente: {motivo}")
            return
        enviar(servidor, confirmacion)
        listo = recibir(servidor)
        if listo is None or _es_error(listo):
            self.resultado = "detectado"
            motivo = listo.get("motivo") if listo else "conexion cerrada"
            self._log(f"[x] ATAQUE DETECTADO por el servidor: {motivo}")
            if listo:
                enviar(cliente, listo)
            return
        enviar(cliente, listo)

        # Nadie detecto el cambio: el atacante calcula las claves de ambos lados.
        A, B = int(hola["A"], 16), int(respuesta["B"], 16)
        nonce_c = bytes.fromhex(hola["nonce"])
        nonce_s = bytes.fromhex(respuesta["nonce"])
        con_cliente = derivar_claves_sesion(
            calcular_secreto(grupo, eva.privada, A),
            calcular_transcripcion(nombre_grupo, modo, A, eva.publica, nonce_c, nonce_s, 0, 0))
        con_servidor = derivar_claves_sesion(
            calcular_secreto(grupo, eva.privada, B),
            calcular_transcripcion(nombre_grupo, modo, eva.publica, B, nonce_c, nonce_s, 0, 0))
        canal_cliente = CanalSeguro(bytes(con_cliente.servidor_a_cliente),
                                    bytes(con_cliente.cliente_a_servidor))
        canal_servidor = CanalSeguro(bytes(con_servidor.cliente_a_servidor),
                                     bytes(con_servidor.servidor_a_cliente))
        self.resultado = "exitoso"
        self._log("[!] ATAQUE EXITOSO: nadie verifico identidades.")
        self._log(f"      clave compartida con el cliente : huella {con_cliente.huella}")
        self._log(f"      clave compartida con el servidor: huella {con_servidor.huella}")

        while True:
            mensaje = recibir(cliente)
            if mensaje is None:
                break
            claro = canal_cliente.descifrar(bytes.fromhex(mensaje["carga"]))
            self.capturados.append(claro)
            self._log(f"[!] MENSAJE LEIDO EN CLARO: {claro.decode('utf-8', 'replace')!r}")
            enviar(servidor, {"tipo": "datos", "carga": canal_servidor.cifrar(claro).hex()})

            respuesta = recibir(servidor)
            if respuesta is None:
                break
            claro = canal_servidor.descifrar(bytes.fromhex(respuesta["carga"]))
            self._log(f"[!] RESPUESTA LEIDA EN CLARO: {claro.decode('utf-8', 'replace')!r}")
            enviar(cliente, {"tipo": "datos", "carga": canal_cliente.cifrar(claro).hex()})

    def cerrar(self) -> None:
        self._socket.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Atacante en el medio (demostracion academica)")
    parser.add_argument("--modo", choices=MODOS, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=6000, help="puerto donde escucha el atacante")
    parser.add_argument("--destino-host", default="127.0.0.1")
    parser.add_argument("--destino-puerto", type=int, default=5000, help="puerto del servidor real")
    args = parser.parse_args()

    atacante = Atacante(args.host, args.puerto,
                        args.destino_host, args.destino_puerto, args.modo)
    print(f"Atacante ({args.modo}) escuchando en {args.host}:{atacante.puerto} "
          f"-> servidor real {args.destino_host}:{args.destino_puerto}")
    print("Ctrl+C para detener.")
    try:
        while True:
            atacante.atender_una()
    except KeyboardInterrupt:
        print("\nAtacante detenido.")
    finally:
        atacante.cerrar()


if __name__ == "__main__":
    main()
