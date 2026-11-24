"""Genera las claves de identidad (firma Schnorr) del servidor y del cliente.

Uso (desde la raiz del proyecto):
    python src/generar_identidades.py
    python src/generar_identidades.py --forzar     # reemplaza las existentes

Crea en la carpeta 'claves/':
    servidor.json       clave privada + publica del servidor  (SECRETO)
    servidor.pub.json   solo la clave publica (se entrega al cliente)
    cliente.json        clave privada + publica del cliente   (SECRETO)
    cliente.pub.json    solo la clave publica (se entrega al servidor)

Los archivos con clave privada no se suben al repositorio (.gitignore).
"""

import argparse
from pathlib import Path

from protocolo.identidad import Identidad


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera identidades de cliente y servidor")
    parser.add_argument("--claves", default="claves", help="carpeta de salida")
    parser.add_argument("--forzar", action="store_true", help="reemplaza las existentes")
    args = parser.parse_args()

    carpeta = Path(args.claves)
    if (carpeta / "servidor.json").exists() and not args.forzar:
        raise SystemExit(f"Ya existen identidades en '{carpeta}'. Use --forzar para reemplazarlas.")

    for nombre in ("servidor", "cliente"):
        identidad = Identidad.generar(nombre)
        identidad.guardar(carpeta / f"{nombre}.json", incluir_privada=True)
        identidad.guardar(carpeta / f"{nombre}.pub.json", incluir_privada=False)
        print(f"{nombre:<9} huella de la clave publica: {identidad.huella()}")
    print(f"Identidades guardadas en '{carpeta}/'.")


if __name__ == "__main__":
    main()
