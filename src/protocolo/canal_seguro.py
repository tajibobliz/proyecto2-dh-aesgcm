"""Canal seguro con cifrado autenticado AES-256-GCM.

AES-GCM es un modo AEAD (cifrado autenticado con datos asociados): en una
sola operacion cifra el mensaje (confidencialidad) y calcula una etiqueta
de 128 bits (integridad y autenticidad). Si un atacante cambia un solo
bit del cifrado, de la etiqueta o de los datos asociados, el descifrado
falla y no se entrega nada.

- AES-256 en modo contador (CTR) hace el cifrado.
- GHASH (multiplicaciones en el cuerpo finito GF(2^128)) hace la etiqueta.

Regla critica de GCM: con una misma clave, el nonce de 96 bits JAMAS se
repite. Si se repite, se filtra el XOR de los textos en claro y se puede
falsificar la autenticacion. Aqui se garantiza asi:

- Cada sentido de la comunicacion tiene su propia clave.
- El nonce es un contador de mensajes que solo crece.

El mismo contador da proteccion contra repeticion (replay): el receptor
solo acepta el numero de secuencia que esta esperando.

AES-GCM es criptografia simetrica, por lo que se usa la primitiva de la
libreria 'cryptography'. Todo el acuerdo de claves que alimenta este
canal (DH, SHA-256, HKDF, firma) es implementacion propia.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from protocolo.errores import ErrorCanal
from protocolo.memoria import borrar

TAM_CLAVE = 32        # AES-256
TAM_SECUENCIA = 8     # bytes del numero de secuencia
TAM_ETIQUETA = 16     # bytes de la etiqueta GCM


class CanalSeguro:
    """Canal bidireccional: una clave para enviar y otra para recibir."""

    def __init__(self, clave_envio: bytes, clave_recepcion: bytes) -> None:
        if len(clave_envio) != TAM_CLAVE or len(clave_recepcion) != TAM_CLAVE:
            raise ValueError("Las claves deben ser de 32 bytes (AES-256)")
        self._clave_envio = bytearray(clave_envio)
        self._clave_recepcion = bytearray(clave_recepcion)
        self._aes_envio = AESGCM(bytes(self._clave_envio))
        self._aes_recepcion = AESGCM(bytes(self._clave_recepcion))
        self._sec_envio = 0
        self._sec_recepcion = 0
        self._abierto = True

    @staticmethod
    def _nonce(secuencia: int) -> bytes:
        """Nonce de 96 bits: 4 bytes en cero + contador de 64 bits."""
        return bytes(4) + secuencia.to_bytes(TAM_SECUENCIA, "big")

    def cifrar(self, claro: bytes, asociado: bytes = b"") -> bytes:
        """Devuelve: secuencia (8 bytes) || cifrado || etiqueta (16 bytes)."""
        self._exigir_abierto()
        cabecera = self._sec_envio.to_bytes(TAM_SECUENCIA, "big")
        cifrado = self._aes_envio.encrypt(
            self._nonce(self._sec_envio), claro, cabecera + asociado)
        self._sec_envio += 1
        return cabecera + cifrado

    def descifrar(self, paquete: bytes, asociado: bytes = b"") -> bytes:
        """Verifica y descifra. Lanza ErrorCanal ante cualquier anomalia."""
        self._exigir_abierto()
        if len(paquete) < TAM_SECUENCIA + TAM_ETIQUETA:
            raise ErrorCanal("Paquete demasiado corto")

        cabecera = paquete[:TAM_SECUENCIA]
        secuencia = int.from_bytes(cabecera, "big")
        if secuencia != self._sec_recepcion:
            raise ErrorCanal(
                f"Numero de secuencia {secuencia} inesperado (se esperaba "
                f"{self._sec_recepcion}): mensaje repetido o reordenado")
        try:
            claro = self._aes_recepcion.decrypt(
                self._nonce(secuencia), paquete[TAM_SECUENCIA:], cabecera + asociado)
        except InvalidTag:
            raise ErrorCanal(
                "Etiqueta de autenticacion invalida: el mensaje fue alterado "
                "o la clave no coincide") from None
        self._sec_recepcion += 1
        return claro

    def cerrar(self) -> None:
        """Borra las claves de memoria. El canal queda inutilizable."""
        borrar(self._clave_envio)
        borrar(self._clave_recepcion)
        self._aes_envio = None
        self._aes_recepcion = None
        self._abierto = False

    def _exigir_abierto(self) -> None:
        if not self._abierto:
            raise ErrorCanal("El canal esta cerrado y sus claves borradas")

    def __enter__(self) -> "CanalSeguro":
        return self

    def __exit__(self, *_) -> None:
        self.cerrar()
