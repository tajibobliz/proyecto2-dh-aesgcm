"""Claves de identidad de larga duracion (para firmar el intercambio).

Hay dos tipos de claves en el sistema:

- Efimeras (Diffie-Hellman): nuevas en cada conexion. Dan secreto
  perfecto hacia adelante (forward secrecy): si manana roban la clave
  de identidad, las conversaciones de hoy siguen siendo secretas.
- De identidad (Schnorr): fijas, guardadas en un archivo. Identifican
  al cliente y al servidor.

Modelo de confianza: claves publicas fijadas (key pinning), como el
archivo known_hosts de SSH. Cada parte conoce de antemano la clave
publica de la otra. Una PKI con certificados X.509 resolveria la
distribucion a gran escala, y queda como mejora futura.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from hashing.sha256 import sha256
from nucleo.primos import GrupoDH
from protocolo import schnorr
from protocolo.codificacion import int_a_bytes
from protocolo.dh import tam_bytes, validar_clave_publica
from protocolo.grupos import obtener_grupo


@dataclass
class Identidad:
    nombre: str
    nombre_grupo: str
    publica: int
    privada: int | None = None        # None si solo se conoce la parte publica

    @property
    def grupo(self) -> GrupoDH:
        return obtener_grupo(self.nombre_grupo)

    @classmethod
    def generar(cls, nombre: str, nombre_grupo: str = "rfc3526-2048") -> "Identidad":
        privada, publica = schnorr.generar_claves(obtener_grupo(nombre_grupo))
        return cls(nombre=nombre, nombre_grupo=nombre_grupo,
                   publica=publica, privada=privada)

    def solo_publica(self) -> "Identidad":
        return Identidad(self.nombre, self.nombre_grupo, self.publica)

    def huella(self) -> str:
        """Resumen corto de la clave publica, comodo para comparar a ojo."""
        n = tam_bytes(self.grupo)
        return sha256(int_a_bytes(self.publica, n)).hex()[:16]

    def guardar(self, ruta: Path, incluir_privada: bool) -> None:
        datos = {"nombre": self.nombre, "grupo": self.nombre_grupo,
                 "publica": format(self.publica, "x")}
        if incluir_privada:
            if self.privada is None:
                raise ValueError("Esta identidad no tiene clave privada")
            datos["privada"] = format(self.privada, "x")
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text(json.dumps(datos, indent=2), encoding="utf-8")

    @classmethod
    def cargar(cls, ruta: Path) -> "Identidad":
        datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
        identidad = cls(
            nombre=datos["nombre"],
            nombre_grupo=datos["grupo"],
            publica=int(datos["publica"], 16),
            privada=int(datos["privada"], 16) if "privada" in datos else None,
        )
        # Zero-Trust: tambien se valida lo que se lee del disco.
        validar_clave_publica(identidad.grupo, identidad.publica)
        return identidad
