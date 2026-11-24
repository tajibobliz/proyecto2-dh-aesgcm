"""Pruebas del handshake completo, incluido el ataque Man-in-the-Middle,
simulado en memoria (sin red)."""

import copy

import pytest

from protocolo.canal_seguro import CanalSeguro
from protocolo.dh import ParClavesDH, calcular_secreto
from protocolo.errores import ErrorCanal, ErrorProtocolo
from protocolo.grupos import GRUPO_RFC3526_2048
from protocolo.handshake import (
    SesionCliente,
    SesionServidor,
    calcular_transcripcion,
    derivar_claves_sesion,
)
from protocolo.identidad import Identidad

GRUPO = GRUPO_RFC3526_2048
NOMBRE = "rfc3526-2048"


def _sesiones(id_cliente, id_servidor):
    cliente = SesionCliente(id_cliente, id_servidor.publica)
    servidor = SesionServidor(id_servidor, (id_cliente.publica,))
    return cliente, servidor


def _completar(cliente, servidor):
    respuesta = servidor.procesar_hola(cliente.crear_hola())
    confirmacion = cliente.procesar_respuesta(respuesta)
    cliente.procesar_listo(servidor.procesar_confirmacion(confirmacion))
    return cliente.canal(), servidor.canal()


def test_handshake_autenticado_completo(id_cliente, id_servidor):
    cliente, servidor = _sesiones(id_cliente, id_servidor)
    canal_c, canal_s = _completar(cliente, servidor)

    assert cliente.claves.huella == servidor.claves.huella
    assert cliente.claves.cliente_a_servidor == servidor.claves.cliente_a_servidor
    assert cliente.claves.servidor_a_cliente == servidor.claves.servidor_a_cliente
    assert cliente.claves.cliente_a_servidor != cliente.claves.servidor_a_cliente

    assert canal_s.descifrar(canal_c.cifrar(b"hola servidor")) == b"hola servidor"
    assert canal_c.descifrar(canal_s.cifrar(b"hola cliente")) == b"hola cliente"


def test_cada_sesion_tiene_claves_nuevas(id_cliente, id_servidor):
    huellas = set()
    for _ in range(3):
        cliente, servidor = _sesiones(id_cliente, id_servidor)
        _completar(cliente, servidor)
        huellas.add(cliente.claves.huella)
    assert len(huellas) == 3


def test_el_servidor_no_entrega_canal_antes_de_verificar_al_cliente(id_cliente, id_servidor):
    cliente, servidor = _sesiones(id_cliente, id_servidor)
    servidor.procesar_hola(cliente.crear_hola())
    with pytest.raises(ErrorProtocolo):
        servidor.canal()


def test_servidor_falso_es_detectado(id_cliente, id_servidor, id_intruso):
    # El intruso se hace pasar por el servidor con su propia clave.
    cliente = SesionCliente(id_cliente, id_servidor.publica)
    servidor_falso = SesionServidor(id_intruso, (id_cliente.publica,))
    respuesta = servidor_falso.procesar_hola(cliente.crear_hola())
    with pytest.raises(ErrorProtocolo, match="INVALIDA"):
        cliente.procesar_respuesta(respuesta)


def test_cliente_no_autorizado_es_rechazado(id_servidor, id_intruso):
    cliente = SesionCliente(id_intruso, id_servidor.publica)
    servidor = SesionServidor(id_servidor, publicas_autorizadas=())
    with pytest.raises(ErrorProtocolo, match="no autorizado"):
        servidor.procesar_hola(cliente.crear_hola())


def test_suplantar_la_identidad_del_cliente_falla(id_cliente, id_servidor, id_intruso):
    # El intruso declara la clave publica del cliente legitimo, pero
    # firma con su propia clave privada.
    impostor = Identidad("cliente", NOMBRE, id_cliente.publica, id_intruso.privada)
    cliente = SesionCliente(impostor, id_servidor.publica)
    servidor = SesionServidor(id_servidor, (id_cliente.publica,))
    confirmacion = cliente.procesar_respuesta(servidor.procesar_hola(cliente.crear_hola()))
    with pytest.raises(ErrorProtocolo, match="INVALIDA"):
        servidor.procesar_confirmacion(confirmacion)


def test_mitm_es_detectado_en_modo_autenticado(id_cliente, id_servidor):
    """El atacante sustituye A y B por su propio valor E, reenviando la
    firma original del servidor. La firma cubre la transcripcion, que
    incluye A y B, asi que el cliente la rechaza."""
    cliente, servidor = _sesiones(id_cliente, id_servidor)
    eva = ParClavesDH.generar(GRUPO)

    hola = cliente.crear_hola()
    hola_falso = dict(hola, A=format(eva.publica, "x"))
    respuesta = servidor.procesar_hola(hola_falso)
    respuesta_falsa = dict(respuesta, B=format(eva.publica, "x"))

    with pytest.raises(ErrorProtocolo, match="Man-in-the-Middle"):
        cliente.procesar_respuesta(respuesta_falsa)


def test_mitm_tiene_exito_en_modo_anonimo():
    """Sin firmas, el mismo ataque funciona: Eva negocia una clave con
    cada parte y lee todo, sin que ninguno lo note."""
    cliente = SesionCliente()                                  # anonimo
    servidor = SesionServidor(permitir_anonimo=True)
    eva = ParClavesDH.generar(GRUPO)
    E = eva.publica

    hola = cliente.crear_hola()
    respuesta = servidor.procesar_hola(dict(hola, A=format(E, "x")))
    confirmacion = cliente.procesar_respuesta(dict(respuesta, B=format(E, "x")))
    cliente.procesar_listo(servidor.procesar_confirmacion(confirmacion))

    # Cliente y servidor creen estar conectados, pero con claves distintas.
    assert cliente.claves.huella != servidor.claves.huella

    # Eva calcula las claves de ambos lados.
    A, B = int(hola["A"], 16), int(respuesta["B"], 16)
    nc, ns = bytes.fromhex(hola["nonce"]), bytes.fromhex(respuesta["nonce"])
    claves_con_cliente = derivar_claves_sesion(
        calcular_secreto(GRUPO, eva.privada, A),
        calcular_transcripcion(NOMBRE, "anonimo", A, E, nc, ns, 0, 0))
    claves_con_servidor = derivar_claves_sesion(
        calcular_secreto(GRUPO, eva.privada, B),
        calcular_transcripcion(NOMBRE, "anonimo", E, B, nc, ns, 0, 0))
    eva_hacia_cliente = CanalSeguro(bytes(claves_con_cliente.servidor_a_cliente),
                                    bytes(claves_con_cliente.cliente_a_servidor))
    eva_hacia_servidor = CanalSeguro(bytes(claves_con_servidor.cliente_a_servidor),
                                     bytes(claves_con_servidor.servidor_a_cliente))

    # Eva lee el mensaje, lo modifica y lo reenvia.
    paquete = cliente.canal().cifrar(b"mi clave bancaria es 1234")
    interceptado = eva_hacia_cliente.descifrar(paquete)
    assert interceptado == b"mi clave bancaria es 1234"
    reenviado = eva_hacia_servidor.cifrar(b"mi clave bancaria es 9999")
    assert servidor.canal().descifrar(reenviado) == b"mi clave bancaria es 9999"


def test_servidor_rechaza_modo_anonimo_por_defecto(id_servidor, id_cliente):
    servidor = SesionServidor(id_servidor, (id_cliente.publica,))
    with pytest.raises(ErrorProtocolo, match="exige autenticacion"):
        servidor.procesar_hola(SesionCliente().crear_hola())


def test_servidor_rechaza_grupo_debil(id_servidor):
    # Ataque de degradacion: forzar un grupo de 512 bits.
    servidor = SesionServidor(id_servidor, permitir_anonimo=True)
    hola = SesionCliente(nombre_grupo="demo-512").crear_hola()
    with pytest.raises(ErrorProtocolo, match="Grupo no permitido"):
        servidor.procesar_hola(hola)


@pytest.mark.parametrize("campo, valor", [
    ("A", "0"), ("A", "1"), ("A", "zz"), ("A", None),
    ("nonce", "abcd"), ("nonce", 12345),
    ("tipo", "otro"), ("modo", "raro"),
])
def test_servidor_rechaza_mensajes_malformados(id_servidor, campo, valor):
    servidor = SesionServidor(id_servidor, permitir_anonimo=True)
    hola = SesionCliente().crear_hola()
    hola[campo] = valor
    with pytest.raises(ErrorProtocolo):
        servidor.procesar_hola(hola)


def test_cliente_rechaza_B_malicioso():
    for malicioso in ("0", "1", format(GRUPO.p - 1, "x")):
        cliente = SesionCliente()
        servidor = SesionServidor(permitir_anonimo=True)
        respuesta = servidor.procesar_hola(cliente.crear_hola())
        with pytest.raises(ErrorProtocolo):
            cliente.procesar_respuesta(dict(respuesta, B=malicioso))


def test_firma_grabada_no_sirve_en_otra_sesion(id_cliente, id_servidor):
    # Ataque de repeticion del handshake: se reenvia una respuesta vieja.
    cliente1, servidor1 = _sesiones(id_cliente, id_servidor)
    respuesta_vieja = servidor1.procesar_hola(cliente1.crear_hola())

    cliente2, _ = _sesiones(id_cliente, id_servidor)
    cliente2.crear_hola()
    with pytest.raises(ErrorProtocolo, match="INVALIDA"):
        cliente2.procesar_respuesta(copy.deepcopy(respuesta_vieja))


def test_claves_de_sesiones_distintas_no_son_intercambiables(id_cliente, id_servidor):
    c1, s1 = _sesiones(id_cliente, id_servidor)
    canal_c1, _ = _completar(c1, s1)
    c2, s2 = _sesiones(id_cliente, id_servidor)
    _, canal_s2 = _completar(c2, s2)
    with pytest.raises(ErrorCanal):
        canal_s2.descifrar(canal_c1.cifrar(b"hola"))
