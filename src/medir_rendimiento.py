"""Medicion de rendimiento de todas las operaciones del sistema.

Uso (desde la raiz del proyecto):
    python src/medir_rendimiento.py              # completo (menos de un minuto)
    python src/medir_rendimiento.py --rapido     # menos repeticiones

Imprime tablas en consola y guarda los datos en
docs/resultados_rendimiento.csv para graficarlos en el informe.

Metodo: cada operacion se repite varias veces y se informa la mediana,
que es mas estable que el promedio frente a picos del sistema.
"""

import argparse
import csv
import secrets
import statistics
import time
from pathlib import Path


from hashing.hmac_hkdf import hkdf, hmac_sha256
from hashing.sha256 import sha256
from nucleo.aritmetica import exp_mod
from nucleo.primalidad import es_primo
from nucleo.primos import generar_grupo
from protocolo import schnorr
from protocolo.dh import ParClavesDH, calcular_secreto, validar_clave_publica
from protocolo.grupos import obtener_grupo
from protocolo.handshake import SesionCliente, SesionServidor
from protocolo.identidad import Identidad
from simetrico.gcm import AESGCMPropio

GRUPOS = ("demo-512", "demo-1024", "rfc3526-2048")
filas_csv: list[tuple[str, str, float]] = []


def medir(funcion, repeticiones: int) -> float:
    """Mediana del tiempo de ejecucion de 'funcion', en milisegundos."""
    tiempos = []
    for _ in range(repeticiones):
        inicio = time.perf_counter()
        funcion()
        tiempos.append((time.perf_counter() - inicio) * 1000)
    return statistics.median(tiempos)


def tabla(titulo: str, encabezados: list[str], filas: list[list[str]]) -> None:
    anchos = [max(len(str(f[i])) for f in [encabezados] + filas) for i in range(len(encabezados))]
    print(f"\n{titulo}")
    print("  " + "  ".join(h.ljust(a) for h, a in zip(encabezados, anchos)))
    print("  " + "  ".join("-" * a for a in anchos))
    for fila in filas:
        print("  " + "  ".join(str(c).ljust(a) for c, a in zip(fila, anchos)))


def registrar(operacion: str, parametro: str, ms: float) -> str:
    filas_csv.append((operacion, parametro, round(ms, 4)))
    return f"{ms:.2f}"


def medir_grupo(nombre: str, rep: int) -> list[str]:
    grupo = obtener_grupo(nombre)
    base = secrets.randbelow(grupo.p - 3) + 2
    exponente = secrets.randbelow(grupo.q - 1) + 1
    alice, bob = ParClavesDH.generar(grupo), ParClavesDH.generar(grupo)
    privada, publica = schnorr.generar_claves(grupo)
    firma = schnorr.firmar(grupo, privada, b"mensaje")
    bits = str(grupo.bits)

    return [
        bits,
        registrar("exp_mod propio", bits, medir(lambda: exp_mod(base, exponente, grupo.p), rep)),
        registrar("pow nativo", bits, medir(lambda: pow(base, exponente, grupo.p), rep)),
        registrar("DH generar par", bits, medir(lambda: ParClavesDH.generar(grupo), rep)),
        registrar("DH validar publica", bits, medir(lambda: validar_clave_publica(grupo, bob.publica), rep)),
        registrar("DH secreto", bits, medir(lambda: calcular_secreto(grupo, alice.privada, bob.publica), rep)),
        registrar("Schnorr firmar", bits, medir(lambda: schnorr.firmar(grupo, privada, b"mensaje"), rep)),
        registrar("Schnorr verificar", bits, medir(lambda: schnorr.verificar(grupo, publica, b"mensaje", firma), rep)),
    ]


def medir_handshake(nombre: str, rep: int) -> list[str]:
    grupos = frozenset({nombre})
    id_s, id_c = Identidad.generar("servidor", nombre), Identidad.generar("cliente", nombre)

    def autenticado():
        cliente = SesionCliente(id_c, id_s.publica, nombre)
        servidor = SesionServidor(id_s, (id_c.publica,), grupos_permitidos=grupos)
        confirmacion = cliente.procesar_respuesta(servidor.procesar_hola(cliente.crear_hola()))
        cliente.procesar_listo(servidor.procesar_confirmacion(confirmacion))

    def anonimo():
        cliente = SesionCliente(nombre_grupo=nombre)
        servidor = SesionServidor(permitir_anonimo=True, grupos_permitidos=grupos)
        confirmacion = cliente.procesar_respuesta(servidor.procesar_hola(cliente.crear_hola()))
        cliente.procesar_listo(servidor.procesar_confirmacion(confirmacion))

    bits = str(obtener_grupo(nombre).bits)
    t_anonimo = medir(anonimo, rep)
    t_autenticado = medir(autenticado, rep)
    return [
        bits,
        registrar("handshake anonimo", bits, t_anonimo),
        registrar("handshake autenticado", bits, t_autenticado),
        f"{t_autenticado / t_anonimo:.1f}x",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark del proyecto")
    parser.add_argument("--rapido", action="store_true", help="menos repeticiones")
    args = parser.parse_args()
    rep = 3 if args.rapido else 9

    print("Midiendo... (los tiempos dependen del equipo)")

    filas = [medir_grupo(nombre, rep) for nombre in GRUPOS]
    tabla("1. Operaciones asimetricas (ms, mediana)",
          ["bits", "exp_mod", "pow nativo", "DH par", "DH validar", "DH secreto",
           "firmar", "verificar"], filas)

    filas = [medir_handshake(nombre, max(3, rep // 3)) for nombre in GRUPOS]
    tabla("2. Handshake completo, cliente + servidor en memoria (ms)",
          ["bits", "anonimo", "autenticado", "costo de autenticar"], filas)

    filas = []
    for bits in (256, 384, 512):
        tiempos = []
        for _ in range(2 if args.rapido else 5):
            inicio = time.perf_counter()
            generar_grupo(bits)
            tiempos.append((time.perf_counter() - inicio) * 1000)
        filas.append([str(bits),
                      registrar("generar primo seguro (mediana)", str(bits), statistics.median(tiempos)),
                      f"{min(tiempos):.2f}", f"{max(tiempos):.2f}"])
    tabla("3. Generacion de primo seguro p = 2q + 1 y generador (ms)",
          ["bits", "mediana", "minimo", "maximo"], filas)

    filas = []
    for nombre in GRUPOS:
        p = obtener_grupo(nombre).p
        bits = str(p.bit_length())
        filas.append([bits, registrar("Miller-Rabin 40 rondas", bits, medir(lambda: es_primo(p), 3))])
    tabla("4. Prueba de primalidad Miller-Rabin, 40 rondas sobre un primo (ms)",
          ["bits", "tiempo"], filas)

    datos = secrets.token_bytes(100_000)
    clave = secrets.token_bytes(32)
    aes_propio = AESGCMPropio(clave)
    t_aes_propio = medir(lambda: aes_propio.encrypt(secrets.token_bytes(12), datos, None), 3)
    filas_aes = [["AES-256-GCM propio, 100 kB", f"{t_aes_propio:.1f}",
                  f"{0.1 / (t_aes_propio / 1000):.2f} MB/s"]]
    registrar("AES-256-GCM propio 100 kB", "-", t_aes_propio)
    try:
        # Solo para comparar: la libreria no forma parte del sistema por defecto.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes = AESGCM(clave)
        grande = secrets.token_bytes(10_000_000)
        t_aes = medir(lambda: aes.encrypt(secrets.token_bytes(12), grande, None), 5)
        registrar("AES-256-GCM libreria 10 MB", "-", t_aes)
        filas_aes.append(["AES-256-GCM (libreria), 10 MB", f"{t_aes:.1f}",
                          f"{10 / (t_aes / 1000):.0f} MB/s"])
    except ImportError:
        pass
    t_sha = medir(lambda: sha256(datos), 3)
    t_hmac = medir(lambda: hmac_sha256(clave, datos), 3)
    t_hkdf = medir(lambda: hkdf(clave, info=b"clave"), 9)
    registrar("SHA-256 propio 100 kB", "-", t_sha)
    registrar("HMAC-SHA256 propio 100 kB", "-", t_hmac)
    registrar("HKDF 32 bytes", "-", t_hkdf)
    tabla("5. Operaciones simetricas",
          ["operacion", "tiempo (ms)", "velocidad"],
          [["SHA-256 propio, 100 kB", f"{t_sha:.1f}", f"{0.1 / (t_sha / 1000):.2f} MB/s"],
           ["HMAC-SHA256 propio, 100 kB", f"{t_hmac:.1f}", f"{0.1 / (t_hmac / 1000):.2f} MB/s"],
           ["HKDF, clave de 32 bytes", f"{t_hkdf:.2f}", "-"]] + filas_aes)

    salida = Path("docs") / "resultados_rendimiento.csv"
    salida.parent.mkdir(exist_ok=True)
    with salida.open("w", newline="", encoding="utf-8") as archivo:
        escritor = csv.writer(archivo)
        escritor.writerow(["operacion", "bits", "milisegundos"])
        escritor.writerows(filas_csv)
    print(f"\nDatos guardados en {salida}")


if __name__ == "__main__":
    main()
