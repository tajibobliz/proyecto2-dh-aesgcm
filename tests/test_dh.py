"""Pruebas del intercambio Diffie-Hellman."""

import pytest

from nucleo.aritmetica import exp_mod
from nucleo.primos import GrupoDH
from protocolo.dh import ParClavesDH, calcular_secreto, tam_bytes, validar_clave_publica
from protocolo.errores import ErrorProtocolo
from protocolo.grupos import GRUPO_DEMO_512, GRUPO_RFC3526_2048


def test_ejemplo_de_libro_con_numeros_chicos():
    # p = 23, q = 11, g = 4. Alice a = 3, Bob b = 7.
    grupo = GrupoDH(p=23, q=11, g=4)
    A = exp_mod(4, 3, 23)                  # 18
    B = exp_mod(4, 7, 23)                  # 8
    assert (A, B) == (18, 8)
    s_alice = calcular_secreto(grupo, 3, B)
    s_bob = calcular_secreto(grupo, 7, A)
    assert s_alice == s_bob == bytearray([exp_mod(4, 21, 23)])


@pytest.mark.parametrize("grupo", [GRUPO_DEMO_512, GRUPO_RFC3526_2048])
def test_ambas_partes_obtienen_el_mismo_secreto(grupo):
    alice = ParClavesDH.generar(grupo)
    bob = ParClavesDH.generar(grupo)
    s_alice = calcular_secreto(grupo, alice.privada, bob.publica)
    s_bob = calcular_secreto(grupo, bob.privada, alice.publica)
    assert s_alice == s_bob
    assert len(s_alice) == tam_bytes(grupo)


def test_cada_sesion_produce_un_secreto_distinto():
    grupo = GRUPO_DEMO_512
    secretos = set()
    for _ in range(5):
        a, b = ParClavesDH.generar(grupo), ParClavesDH.generar(grupo)
        secretos.add(bytes(calcular_secreto(grupo, a.privada, b.publica)))
    assert len(secretos) == 5


def test_un_tercero_no_obtiene_el_secreto():
    grupo = GRUPO_DEMO_512
    alice, bob, eva = (ParClavesDH.generar(grupo) for _ in range(3))
    secreto = calcular_secreto(grupo, alice.privada, bob.publica)
    assert calcular_secreto(grupo, eva.privada, bob.publica) != secreto
    assert calcular_secreto(grupo, eva.privada, alice.publica) != secreto


def test_claves_publicas_maliciosas_son_rechazadas():
    grupo = GRUPO_DEMO_512
    alice = ParClavesDH.generar(grupo)
    for maliciosa in (0, 1, grupo.p - 1, grupo.p, grupo.p + 5, -3):
        with pytest.raises(ErrorProtocolo):
            calcular_secreto(grupo, alice.privada, maliciosa)


def test_elemento_fuera_del_subgrupo_es_rechazado():
    # Ataque de confinamiento a subgrupo pequeno: se busca un elemento
    # de orden 2q (fuera del subgrupo de orden q).
    grupo = GRUPO_DEMO_512
    h = 2
    while exp_mod(h, grupo.q, grupo.p) == 1:
        h += 1
    with pytest.raises(ErrorProtocolo):
        validar_clave_publica(grupo, h)


def test_clave_publica_valida_es_aceptada():
    grupo = GRUPO_DEMO_512
    validar_clave_publica(grupo, ParClavesDH.generar(grupo).publica)
