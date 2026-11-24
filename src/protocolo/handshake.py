"""Acuerdo de claves autenticado entre cliente y servidor (handshake).

Une todas las piezas del proyecto en un protocolo de 4 mensajes:

    Cliente                                               Servidor
    a, A = g^a                                            b, B = g^b
    1. hola:         grupo, modo, A, nonce_c, id_c  --->
                                                          valida todo
    2. respuesta:    B, nonce_s, firma_servidor     <---
    verifica la firma
    3. confirmacion: firma_cliente                  --->
                                                          verifica la firma
    4. listo                                        <---

    Ambos:  s  = g^(ab) mod p                        (Diffie-Hellman)
            T  = SHA-256(todo lo intercambiado)      (transcripcion)
            claves = HKDF(sal = T, material = s)     (una por sentido)
    Luego: mensajes cifrados con AES-256-GCM.

Por que se firma la transcripcion T:
    T resume TODO lo que cada parte vio (grupo, A, B, nonces, identidades).
    Si un intermediario cambia A o B, el cliente y el servidor calculan
    transcripciones distintas, y la firma recibida no verifica. El ataque
    Man-in-the-Middle queda detectado. Este esquema ("firmar y derivar")
    es la idea central de TLS 1.3 y del protocolo SIGMA.

Los nonces aleatorios hacen unica cada sesion e impiden reutilizar
mensajes grabados de una conexion anterior.

Modo anonimo (sin firmas): existe solo para DEMOSTRAR que Diffie-Hellman
sin autenticar es vulnerable. El servidor lo rechaza por defecto.
"""

import secrets
from dataclasses import dataclass

from hashing.hmac_hkdf import hkdf_expand, hkdf_extract
from hashing.sha256 import sha256
from protocolo import schnorr
from protocolo.canal_seguro import CanalSeguro
from protocolo.codificacion import codificar, int_a_bytes, leer_bytes, leer_entero
from protocolo.dh import ParClavesDH, calcular_secreto, tam_bytes, validar_clave_publica
from protocolo.errores import ErrorProtocolo
from protocolo.grupos import GRUPO_POR_DEFECTO, GRUPOS_SEGUROS, obtener_grupo
from protocolo.identidad import Identidad
from protocolo.memoria import borrar

VERSION = b"ELC107-DH-AES256GCM-v1"
TAM_NONCE = 32
MODO_AUTENTICADO = "autenticado"
MODO_ANONIMO = "anonimo"


@dataclass
class ClavesSesion:
    cliente_a_servidor: bytearray
    servidor_a_cliente: bytearray
    huella: str                       # identificador publico de la sesion


def calcular_transcripcion(nombre_grupo: str, modo: str, A: int, B: int,
                           nonce_c: bytes, nonce_s: bytes,
                           publica_c: int, publica_s: int) -> bytes:
    """Resumen SHA-256 de todo lo intercambiado en el handshake."""
    grupo = obtener_grupo(nombre_grupo)
    n = tam_bytes(grupo)
    return sha256(codificar(
        VERSION,
        nombre_grupo.encode(),
        modo.encode(),
        int_a_bytes(grupo.p, n),
        int_a_bytes(grupo.g, n),
        int_a_bytes(A, n),
        int_a_bytes(B, n),
        nonce_c,
        nonce_s,
        int_a_bytes(publica_c, n),
        int_a_bytes(publica_s, n),
    ))


def derivar_claves_sesion(secreto: bytes, transcripcion: bytes) -> ClavesSesion:
    """Convierte el secreto Diffie-Hellman en las claves AES de la sesion.

    Se deriva una clave distinta por sentido. Asi cada clave tiene su
    propio contador de nonces y nunca se repite un par (clave, nonce).
    """
    prk = bytearray(hkdf_extract(sal=transcripcion, material=bytes(secreto)))
    claves = ClavesSesion(
        cliente_a_servidor=bytearray(hkdf_expand(bytes(prk), b"clave cliente->servidor", 32)),
        servidor_a_cliente=bytearray(hkdf_expand(bytes(prk), b"clave servidor->cliente", 32)),
        huella=hkdf_expand(bytes(prk), b"huella de sesion", 8).hex(),
    )
    borrar(prk)
    return claves


def _firma_a_dict(firma: schnorr.Firma) -> dict:
    return {"e": format(firma.e, "x"), "s": format(firma.s, "x")}


def _leer_firma(mensaje: dict) -> schnorr.Firma:
    datos = mensaje.get("firma")
    if not isinstance(datos, dict):
        raise ErrorProtocolo("Falta la firma digital")
    return schnorr.Firma(e=leer_entero(datos, "e"), s=leer_entero(datos, "s"))


def _exigir_tipo(mensaje: dict, tipo: str) -> None:
    if not isinstance(mensaje, dict):
        raise ErrorProtocolo("Mensaje con formato invalido")
    if mensaje.get("tipo") == "error":
        raise ErrorProtocolo(f"La otra parte aborto: {mensaje.get('motivo')}")
    if mensaje.get("tipo") != tipo:
        raise ErrorProtocolo(f"Se esperaba un mensaje '{tipo}'")


def _leer_nonce(mensaje: dict) -> bytes:
    nonce = leer_bytes(mensaje, "nonce", TAM_NONCE)
    if len(nonce) != TAM_NONCE:
        raise ErrorProtocolo("Nonce de longitud invalida")
    return nonce


class SesionCliente:
    """Lado cliente del handshake.

    Con 'identidad' y 'publica_servidor' trabaja en modo autenticado.
    Sin ellas trabaja en modo anonimo (solo para la demostracion MITM).
    """

    def __init__(self, identidad: Identidad | None = None,
                 publica_servidor: int | None = None,
                 nombre_grupo: str = GRUPO_POR_DEFECTO) -> None:
        self.autenticado = identidad is not None
        if self.autenticado:
            if identidad.privada is None or publica_servidor is None:
                raise ValueError("El modo autenticado necesita la clave privada "
                                 "propia y la clave publica del servidor")
            if identidad.nombre_grupo != nombre_grupo:
                raise ValueError("La identidad pertenece a otro grupo")
        self._identidad = identidad
        self._publica_servidor = publica_servidor or 0
        self.nombre_grupo = nombre_grupo
        self._grupo = obtener_grupo(nombre_grupo)
        self._par: ParClavesDH | None = None
        self._nonce = b""
        self.claves: ClavesSesion | None = None

    @property
    def modo(self) -> str:
        return MODO_AUTENTICADO if self.autenticado else MODO_ANONIMO

    def crear_hola(self) -> dict:
        """Mensaje 1: valor publico efimero A y nonce del cliente."""
        self._par = ParClavesDH.generar(self._grupo)
        self._nonce = secrets.token_bytes(TAM_NONCE)
        hola = {
            "tipo": "hola",
            "grupo": self.nombre_grupo,
            "modo": self.modo,
            "A": format(self._par.publica, "x"),
            "nonce": self._nonce.hex(),
        }
        if self.autenticado:
            hola["identidad"] = format(self._identidad.publica, "x")
        return hola

    def procesar_respuesta(self, mensaje: dict) -> dict:
        """Recibe el mensaje 2, verifica al servidor y arma el mensaje 3."""
        if self._par is None:
            raise ErrorProtocolo("Primero debe enviarse el mensaje 'hola'")
        _exigir_tipo(mensaje, "respuesta")
        B = leer_entero(mensaje, "B")
        nonce_s = _leer_nonce(mensaje)
        validar_clave_publica(self._grupo, B)

        publica_propia = self._identidad.publica if self.autenticado else 0
        transcripcion = calcular_transcripcion(
            self.nombre_grupo, self.modo, self._par.publica, B,
            self._nonce, nonce_s, publica_propia, self._publica_servidor)

        if self.autenticado:
            firma = _leer_firma(mensaje)
            if not schnorr.verificar(self._grupo, self._publica_servidor,
                                     b"servidor" + transcripcion, firma):
                raise ErrorProtocolo(
                    "Firma del servidor INVALIDA: el intercambio fue alterado "
                    "(posible ataque Man-in-the-Middle)")

        secreto = calcular_secreto(self._grupo, self._par.privada, B)
        self.claves = derivar_claves_sesion(secreto, transcripcion)
        borrar(secreto)
        self._par = None                  # se descarta el exponente efimero

        confirmacion = {"tipo": "confirmacion"}
        if self.autenticado:
            firma = schnorr.firmar(self._grupo, self._identidad.privada,
                                   b"cliente" + transcripcion)
            confirmacion["firma"] = _firma_a_dict(firma)
        return confirmacion

    def procesar_listo(self, mensaje: dict) -> None:
        """Recibe el mensaje 4: el servidor acepto la sesion."""
        _exigir_tipo(mensaje, "listo")

    def canal(self, aes: str = "propia") -> CanalSeguro:
        if self.claves is None:
            raise ErrorProtocolo("El handshake no ha terminado")
        return CanalSeguro(clave_envio=bytes(self.claves.cliente_a_servidor),
                           clave_recepcion=bytes(self.claves.servidor_a_cliente),
                           implementacion=aes)


class SesionServidor:
    """Lado servidor del handshake.

    'publicas_autorizadas' es la lista de claves publicas de clientes
    aceptados. 'permitir_anonimo' debe quedar en False salvo para la
    demostracion del ataque MITM.
    """

    def __init__(self, identidad: Identidad | None = None,
                 publicas_autorizadas: tuple[int, ...] = (),
                 permitir_anonimo: bool = False,
                 grupos_permitidos: frozenset[str] = GRUPOS_SEGUROS) -> None:
        if identidad is not None and identidad.privada is None:
            raise ValueError("El servidor necesita su clave privada")
        self._identidad = identidad
        self._autorizadas = set(publicas_autorizadas)
        self._permitir_anonimo = permitir_anonimo
        self._grupos_permitidos = grupos_permitidos
        self._transcripcion = b""
        self._publica_cliente = 0
        self._grupo = None
        self._lista = False
        self.modo = ""
        self.claves: ClavesSesion | None = None

    def procesar_hola(self, mensaje: dict) -> dict:
        """Recibe el mensaje 1, valida todo y arma el mensaje 2."""
        _exigir_tipo(mensaje, "hola")

        nombre_grupo = mensaje.get("grupo")
        if nombre_grupo not in self._grupos_permitidos:
            raise ErrorProtocolo(f"Grupo no permitido: {nombre_grupo!r}")
        self._grupo = obtener_grupo(nombre_grupo)

        self.modo = mensaje.get("modo")
        if self.modo == MODO_ANONIMO:
            if not self._permitir_anonimo:
                raise ErrorProtocolo("Este servidor exige autenticacion")
        elif self.modo == MODO_AUTENTICADO:
            if self._identidad is None:
                raise ErrorProtocolo("El servidor no tiene identidad configurada")
            if self._identidad.nombre_grupo != nombre_grupo:
                raise ErrorProtocolo("La identidad del servidor es de otro grupo")
            self._publica_cliente = leer_entero(mensaje, "identidad")
            if self._publica_cliente not in self._autorizadas:
                raise ErrorProtocolo("Cliente no autorizado: clave publica desconocida")
        else:
            raise ErrorProtocolo("Modo desconocido")

        A = leer_entero(mensaje, "A")
        nonce_c = _leer_nonce(mensaje)
        validar_clave_publica(self._grupo, A)

        par = ParClavesDH.generar(self._grupo)
        nonce_s = secrets.token_bytes(TAM_NONCE)
        autenticado = self.modo == MODO_AUTENTICADO
        self._transcripcion = calcular_transcripcion(
            nombre_grupo, self.modo, A, par.publica, nonce_c, nonce_s,
            self._publica_cliente, self._identidad.publica if autenticado else 0)

        secreto = calcular_secreto(self._grupo, par.privada, A)
        self.claves = derivar_claves_sesion(secreto, self._transcripcion)
        borrar(secreto)

        respuesta = {
            "tipo": "respuesta",
            "B": format(par.publica, "x"),
            "nonce": nonce_s.hex(),
        }
        if autenticado:
            firma = schnorr.firmar(self._grupo, self._identidad.privada,
                                   b"servidor" + self._transcripcion)
            respuesta["firma"] = _firma_a_dict(firma)
        return respuesta

    def procesar_confirmacion(self, mensaje: dict) -> dict:
        """Recibe el mensaje 3, verifica al cliente y arma el mensaje 4."""
        if self.claves is None:
            raise ErrorProtocolo("Primero debe recibirse el mensaje 'hola'")
        _exigir_tipo(mensaje, "confirmacion")
        if self.modo == MODO_AUTENTICADO:
            firma = _leer_firma(mensaje)
            if not schnorr.verificar(self._grupo, self._publica_cliente,
                                     b"cliente" + self._transcripcion, firma):
                raise ErrorProtocolo(
                    "Firma del cliente INVALIDA: el intercambio fue alterado "
                    "(posible ataque Man-in-the-Middle)")
        self._lista = True
        return {"tipo": "listo"}

    def canal(self, aes: str = "propia") -> CanalSeguro:
        if not self._lista:
            raise ErrorProtocolo("El handshake no ha terminado")
        return CanalSeguro(clave_envio=bytes(self.claves.servidor_a_cliente),
                           clave_recepcion=bytes(self.claves.cliente_a_servidor),
                           implementacion=aes)
