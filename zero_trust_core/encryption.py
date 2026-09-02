import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class SessionCipher:
    """Secure per-session cipher using AES-GCM over a shared symmetric secret."""

    _key: bytes

    @classmethod
    def from_shared_secret(cls, secret: str, salt: bytes = b"ztna-default-salt") -> "SessionCipher":
        import hashlib

        digest = hashlib.sha256()
        digest.update(secret.encode("utf-8"))
        digest.update(salt)
        return cls(digest.digest())

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, payload: bytes, associated_data: Optional[bytes] = None) -> bytes:
        if len(payload) < 12 + 16:
            raise ValueError("Payload is too short to be a valid AES-GCM message")
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
