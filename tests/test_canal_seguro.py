"""Pruebas del canal AES-256-GCM: confidencialidad, integridad,
proteccion contra repeticion y borrado de claves."""

import secrets

import pytest

from protocolo.canal_seguro import CanalSeguro
from protocolo.errores import ErrorCanal
from protocolo.memoria import borrar


def _par_de_canales() -> tuple[CanalSeguro, CanalSeguro]:
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    return CanalSeguro(k1, k2), CanalSeguro(k2, k1)


def test_ida_y_vuelta():
    cliente, servidor = _par_de_canales()
    for texto in (b"", b"hola", secrets.token_bytes(5000)):
        assert servidor.descifrar(cliente.cifrar(texto)) == texto
        assert cliente.descifrar(servidor.cifrar(texto)) == texto


def test_el_cifrado_no_revela_el_texto():
    cliente, _ = _par_de_canales()
    claro = b"informacion confidencial del proyecto"
    paquete = cliente.cifrar(claro)
    assert claro not in paquete
    assert len(paquete) == 8 + len(claro) + 16     # secuencia + cifrado + etiqueta


def test_mismo_texto_produce_cifrados_distintos():
    cliente, _ = _par_de_canales()
    assert cliente.cifrar(b"hola")[8:] != cliente.cifrar(b"hola")[8:]


def test_cualquier_bit_alterado_es_detectado():
    cliente, servidor = _par_de_canales()
    paquete = cliente.cifrar(b"transferir 100 Bs")
    # Se altera un bit en el cifrado y otro en la etiqueta.
    for posicion in (8, len(paquete) - 1):
        alterado = bytearray(paquete)
        alterado[posicion] ^= 0x01
        with pytest.raises(ErrorCanal, match="alterado"):
            servidor.descifrar(bytes(alterado))
    assert servidor.descifrar(paquete) == b"transferir 100 Bs"   # el original si pasa


def test_mensaje_repetido_es_rechazado():
    cliente, servidor = _par_de_canales()
    paquete = cliente.cifrar(b"pagar")
    assert servidor.descifrar(paquete) == b"pagar"
    with pytest.raises(ErrorCanal, match="repetido"):
        servidor.descifrar(paquete)


def test_mensajes_fuera_de_orden_son_rechazados():
    cliente, servidor = _par_de_canales()
    cliente.cifrar(b"uno")
    segundo = cliente.cifrar(b"dos")
    with pytest.raises(ErrorCanal):
        servidor.descifrar(segundo)


def test_no_se_puede_reflejar_un_mensaje_al_emisor():
    # Cada sentido usa su propia clave: lo enviado no descifra de vuelta.
    cliente, _ = _par_de_canales()
    paquete = cliente.cifrar(b"hola")
    with pytest.raises(ErrorCanal):
        cliente.descifrar(paquete)


def test_clave_equivocada_no_descifra():
    cliente, _ = _par_de_canales()
    _, otro_servidor = _par_de_canales()
    with pytest.raises(ErrorCanal):
        otro_servidor.descifrar(cliente.cifrar(b"hola"))


def test_datos_asociados_quedan_autenticados():
    cliente, servidor = _par_de_canales()
    paquete = cliente.cifrar(b"hola", asociado=b"cabecera-v1")
    with pytest.raises(ErrorCanal):
        servidor.descifrar(paquete, asociado=b"cabecera-v2")


def test_paquete_truncado_es_rechazado():
    cliente, servidor = _par_de_canales()
    with pytest.raises(ErrorCanal):
        servidor.descifrar(cliente.cifrar(b"hola")[:10])


def test_tamano_de_clave_incorrecto():
    with pytest.raises(ValueError):
        CanalSeguro(bytes(16), bytes(32))


def test_cerrar_borra_las_claves_e_inutiliza_el_canal():
    cliente, _ = _par_de_canales()
    cliente.cerrar()
    assert cliente._clave_envio == bytearray(32)
    assert cliente._clave_recepcion == bytearray(32)
    with pytest.raises(ErrorCanal, match="cerrado"):
        cliente.cifrar(b"hola")


def test_borrar_sobrescribe_con_ceros():
    secreto = bytearray(b"clave muy secreta")
    borrar(secreto)
    assert secreto == bytearray(17)


# ------------------------------------------------- implementacion propia vs libreria
@pytest.mark.parametrize("implementacion", ["propia", "libreria"])
def test_ambas_implementaciones_detectan_alteraciones(implementacion):
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    emisor = CanalSeguro(k1, k2, implementacion)
    receptor = CanalSeguro(k2, k1, implementacion)
    paquete = bytearray(emisor.cifrar(b"pagar 100 Bs"))
    paquete[10] ^= 0x01
    with pytest.raises(ErrorCanal, match="alterado"):
        receptor.descifrar(bytes(paquete))


@pytest.mark.parametrize("emisor_impl, receptor_impl",
                         [("propia", "libreria"), ("libreria", "propia")])
def test_implementaciones_son_interoperables(emisor_impl, receptor_impl):
    # Si la implementacion propia tuviera un solo bit distinto al estandar,
    # la libreria no podria descifrar sus mensajes (ni al reves).
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    emisor = CanalSeguro(k1, k2, emisor_impl)
    receptor = CanalSeguro(k2, k1, receptor_impl)
    for texto in (b"", b"hola", secrets.token_bytes(1000)):
        paquete = emisor.cifrar(texto, asociado=b"v1")
        assert receptor.descifrar(paquete, asociado=b"v1") == texto
        assert emisor.descifrar(receptor.cifrar(texto)) == texto


def test_implementacion_desconocida():
    with pytest.raises(ValueError):
        CanalSeguro(bytes(32), bytes(32), "otra")


def test_por_defecto_se_usa_la_implementacion_propia():
    assert CanalSeguro(bytes(32), bytes(32)).implementacion == "propia"
