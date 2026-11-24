"""Datos compartidos entre pruebas. Las identidades se generan una sola
vez por ejecucion porque cada generacion cuesta una exponenciacion de
2048 bits."""

import pytest

from protocolo.identidad import Identidad


@pytest.fixture(scope="session")
def id_servidor() -> Identidad:
    return Identidad.generar("servidor")


@pytest.fixture(scope="session")
def id_cliente() -> Identidad:
    return Identidad.generar("cliente")


@pytest.fixture(scope="session")
def id_intruso() -> Identidad:
    return Identidad.generar("intruso")
