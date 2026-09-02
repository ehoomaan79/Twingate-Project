from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from .encryption import SessionCipher


@dataclass
class EncryptedEnvelope:
    """Application payload encrypted before it enters the relay transport."""

    ciphertext: str

    @classmethod
    def seal(cls, plaintext: bytes, shared_secret: str, associated_data: bytes = b"") -> "EncryptedEnvelope":
        encrypted = SessionCipher.from_shared_secret(shared_secret).encrypt(plaintext, associated_data)
        return cls(base64.urlsafe_b64encode(encrypted).decode("ascii"))

    def open(self, shared_secret: str, associated_data: bytes = b"") -> bytes:
        encrypted = base64.urlsafe_b64decode(self.ciphertext.encode("ascii"))
        return SessionCipher.from_shared_secret(shared_secret).decrypt(encrypted, associated_data)

    def to_json(self) -> str:
        return json.dumps({"ciphertext": self.ciphertext}, separators=(",", ":"))
