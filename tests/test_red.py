"""Pruebas de extremo a extremo por sockets TCP reales (en localhost):
cliente, servidor y atacante en hilos separados."""

import threading

import pytest

from protocolo.errores import ErrorProtocolo
from protocolo.identidad import Identidad
from red.atacante import Atacante
from red.cliente import ClienteSeguro
from red.servidor import ServidorSeguro


def _en_hilo(objeto) -> threading.Thread:
    hilo = threading.Thread(target=objeto.atender_una, daemon=True)
    hilo.start()
    return hilo


@pytest.fixture
def servidor(id_servidor, id_cliente):
    s = ServidorSeguro("127.0.0.1", 0, id_servidor, (id_cliente.publica,), silencioso=True)
    yield s
    s.cerrar()


@pytest.fixture
def servidor_anonimo(id_servidor, id_cliente):
    s = ServidorSeguro("127.0.0.1", 0, id_servidor, (id_cliente.publica,),
                       permitir_anonimo=True, silencioso=True)
    yield s
    s.cerrar()


def _atacante(servidor, modo) -> Atacante:
    return Atacante("127.0.0.1", 0, "127.0.0.1", servidor.puerto, modo, silencioso=True)


def test_comunicacion_normal(servidor, id_cliente, id_servidor):
    hilo = _en_hilo(servidor)
    with ClienteSeguro("127.0.0.1", servidor.puerto, id_cliente, id_servidor.publica) as c:
        c.conectar()
        assert c.enviar_mensaje(b"hola") == b"recibido: hola"
        assert c.enviar_mensaje("mensaje con ñ y tildes áé".encode()) == \
            "recibido: mensaje con ñ y tildes áé".encode()
    hilo.join(timeout=10)
    assert servidor.recibidos == [b"hola", "mensaje con ñ y tildes áé".encode()]
    assert servidor.errores == []


def test_espia_pasivo_no_obtiene_el_texto(servidor, id_cliente, id_servidor):
    atacante = _atacante(servidor, "pasivo")
    hilos = [_en_hilo(servidor), _en_hilo(atacante)]
    secreto = b"la clave del tesoro es 4815162342"
    with ClienteSeguro("127.0.0.1", atacante.puerto, id_cliente, id_servidor.publica) as c:
        c.conectar()
        assert c.enviar_mensaje(secreto) == b"recibido: " + secreto
    for h in hilos:
        h.join(timeout=10)
    atacante.cerrar()
    assert len(atacante.observados) == 1
    assert secreto not in atacante.observados[0]       # solo vio cifrado
    assert atacante.capturados == []


def test_alteracion_de_un_bit_es_detectada(servidor, id_cliente, id_servidor):
    atacante = _atacante(servidor, "alterar")
    hilos = [_en_hilo(servidor), _en_hilo(atacante)]
    with ClienteSeguro("127.0.0.1", atacante.puerto, id_cliente, id_servidor.publica) as c:
        c.conectar()
        with pytest.raises(ErrorProtocolo, match="alterado"):
            c.enviar_mensaje(b"transferir 100 Bs")
    for h in hilos:
        h.join(timeout=10)
    atacante.cerrar()
    assert atacante.resultado == "detectado"
    assert servidor.recibidos == []                    # nunca se entrego
    assert "alterado" in servidor.errores[0]


def test_repeticion_de_mensaje_es_detectada(servidor, id_cliente, id_servidor):
    atacante = _atacante(servidor, "repetir")
    hilos = [_en_hilo(servidor), _en_hilo(atacante)]
    with ClienteSeguro("127.0.0.1", atacante.puerto, id_cliente, id_servidor.publica) as c:
        c.conectar()
        assert c.enviar_mensaje(b"pagar 100 Bs") == b"recibido: pagar 100 Bs"
    for h in hilos:
        h.join(timeout=10)
    atacante.cerrar()
    assert atacante.resultado == "detectado"
    assert servidor.recibidos == [b"pagar 100 Bs"]     # una sola vez, no dos
    assert "repetido" in servidor.errores[0]


def test_mitm_detectado_con_autenticacion(servidor, id_cliente, id_servidor):
    atacante = _atacante(servidor, "mitm")
    hilos = [_en_hilo(servidor), _en_hilo(atacante)]
    with ClienteSeguro("127.0.0.1", atacante.puerto, id_cliente, id_servidor.publica) as c:
        with pytest.raises(ErrorProtocolo, match="Man-in-the-Middle"):
            c.conectar()
    for h in hilos:
        h.join(timeout=10)
    atacante.cerrar()
    assert atacante.resultado == "detectado"
    assert atacante.capturados == []
    assert servidor.recibidos == []


def test_mitm_exitoso_sin_autenticacion(servidor_anonimo):
    atacante = _atacante(servidor_anonimo, "mitm")
    hilos = [_en_hilo(servidor_anonimo), _en_hilo(atacante)]
    secreto = b"mi clave bancaria es 1234"
    with ClienteSeguro("127.0.0.1", atacante.puerto) as c:           # anonimo
        c.conectar()
        assert c.enviar_mensaje(secreto) == b"recibido: " + secreto  # no nota nada
    for h in hilos:
        h.join(timeout=10)
    atacante.cerrar()
    assert atacante.resultado == "exitoso"
    assert atacante.capturados == [secreto]            # el atacante lo leyo


def test_servidor_rechaza_cliente_anonimo(servidor):
    hilo = _en_hilo(servidor)
    with ClienteSeguro("127.0.0.1", servidor.puerto) as c:
        with pytest.raises(ErrorProtocolo, match="exige autenticacion"):
            c.conectar()
    hilo.join(timeout=10)


def test_servidor_rechaza_cliente_desconocido(servidor, id_intruso, id_servidor):
    hilo = _en_hilo(servidor)
    with ClienteSeguro("127.0.0.1", servidor.puerto, id_intruso, id_servidor.publica) as c:
        with pytest.raises(ErrorProtocolo, match="no autorizado"):
            c.conectar()
    hilo.join(timeout=10)


def test_identidades_se_guardan_y_cargan(tmp_path, id_cliente):
    id_cliente.guardar(tmp_path / "c.json", incluir_privada=True)
    id_cliente.guardar(tmp_path / "c.pub.json", incluir_privada=False)
    completa = Identidad.cargar(tmp_path / "c.json")
    publica = Identidad.cargar(tmp_path / "c.pub.json")
    assert completa.privada == id_cliente.privada
    assert publica.privada is None
    assert publica.publica == id_cliente.publica
    assert "privada" not in (tmp_path / "c.pub.json").read_text()


def test_cliente_propio_con_servidor_libreria(id_servidor, id_cliente):
    servidor = ServidorSeguro("127.0.0.1", 0, id_servidor, (id_cliente.publica,),
                              silencioso=True, aes="libreria")
    hilo = _en_hilo(servidor)
    with ClienteSeguro("127.0.0.1", servidor.puerto, id_cliente, id_servidor.publica,
                       aes="propia") as c:
        c.conectar()
        assert c.enviar_mensaje(b"interoperable") == b"recibido: interoperable"
    hilo.join(timeout=10)
    servidor.cerrar()
