"""Grupos Diffie-Hellman disponibles.

Generar un primo seguro de 2048 bits con codigo Python puede tardar
varios minutos. Por eso, igual que hacen TLS, SSH e IPsec, para el uso
real se emplea un grupo estandar publico:

- rfc3526-2048: grupo 14 del RFC 3526 (MODP de 2048 bits). Su primo es
      p = 2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476)
  Esta construido a partir de los digitos de pi para demostrar que no
  esconde ninguna puerta trasera. Es un primo seguro (p = 2q + 1) y su
  generador g = 2 tiene orden q. Las pruebas lo verifican todo: la
  formula, la primalidad de p y q, y el orden de g.

Usar un grupo publico no debilita el protocolo: la seguridad depende de
los exponentes privados, no de mantener p y g en secreto.

- demo-512 y demo-1024: generados con el codigo propio de este proyecto
  (nucleo/primos.py). Sirven SOLO para comparar tiempos en el benchmark.
  Con 512 o 1024 bits el logaritmo discreto esta al alcance de un
  atacante con recursos, por lo que el servidor no los acepta.
"""

from nucleo.primos import GrupoDH


def _grupo(p_hex: str, g: int) -> GrupoDH:
    p = int(p_hex, 16)
    return GrupoDH(p=p, q=(p - 1) // 2, g=g)


GRUPO_RFC3526_2048 = _grupo(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    2,
)

GRUPO_DEMO_512 = _grupo(
    "E51AB026A21A2D0937D466BF77CF0805A70679A6574789CBA26DF3800CB9F798"
    "0540AF62A415CC8D7840013B74DF99E190ADE5CB139E39F8F307719AF8AF38BF",
    int(
    "C3330BE096F2D404A268F2E5C35EE5DEF8499BC565B5C2250D1948BF060BC385"
    "F54CFC48D3D48DE6D8C11242BFA33C6B7DEC30EB39C51821F018CE8327C306D8",
        16,
    ),
)

GRUPO_DEMO_1024 = _grupo(
    "FFBB2C606E2C90445029A9D800005090A838BFF04DC3764DEED40BBDCF2C1E0B"
    "448E56DA006B34D30142533D9CCEE2C2A257B820DA3F85551E8608B8BAA7FE03"
    "4DB604610739FD667646AB85F1F979339FCA1A8CCD0F86B8B98C3FF40E2E500B"
    "02C3044D40C3041D46091109820D87A9D12A6617618594D147044C4395E21D83",
    int(
    "AF7FD82453FB4CDB203B70FA78443B659D3D1A21614A8086FEDE9AEF7DDA7716"
    "C314519E0397953767F2952C1A4EF73026B92C76956EE94E501030F13DC1B299"
    "16DA36DE3E5F76991B50B39A90C08B1E3E0C18C068B59EC33C4E98B93697AB44"
    "59EF630D001D7D730EF03C5DCF5B63524A494799CDB42ABFAB7D94BB16EAF3B0",
        16,
    ),
)

GRUPO_POR_DEFECTO = "rfc3526-2048"

_REGISTRO = {
    "rfc3526-2048": GRUPO_RFC3526_2048,
    "demo-512": GRUPO_DEMO_512,
    "demo-1024": GRUPO_DEMO_1024,
}

# Politica del servidor: solo grupos de tamano seguro. Evita que un
# atacante fuerce la negociacion de un grupo debil (ataque de degradacion,
# como Logjam contra TLS).
GRUPOS_SEGUROS = frozenset({"rfc3526-2048"})


def obtener_grupo(nombre: str) -> GrupoDH:
    """Devuelve el grupo registrado con ese nombre."""
    try:
        return _REGISTRO[nombre]
    except KeyError:
        raise ValueError(f"Grupo desconocido: {nombre!r}") from None


def nombres_de_grupos() -> list[str]:
    return list(_REGISTRO)
