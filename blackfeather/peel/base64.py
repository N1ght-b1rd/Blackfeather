"""
Decoder de Base64 (padrão e URL-safe).

"""
import base64
import re
from typing import Optional

from .base import BaseDecoder, DecodeResult


# Base64 padrão: [A-Za-z0-9+/] com padding =
_BASE64_STD_RE = re.compile(rb"^[A-Za-z0-9+/]+={0,2}$")

# URL-safe: troca + e / por - e _
_BASE64_URL_RE = re.compile(rb"^[A-Za-z0-9\-_]+={0,2}$")


class Base64Decoder(BaseDecoder):
    name = "Base64"
    priority = 60  # testa depois do hex, que é mais específico

    def detect(self, data: bytes) -> bool:
        if not data or len(data) < 8:
            return False
        stripped = data.strip()
        # Base64 sempre tem tamanho múltiplo de 4 (com padding)
        if len(stripped) % 4 != 0:
            return False
        # URL-safe tem - ou _, que o padrão não tem
        if _BASE64_URL_RE.match(stripped):
            return True
        if _BASE64_STD_RE.match(stripped):
            return True
        return False

    def decode(self, data: bytes) -> bytes:
        stripped = data.strip()
        if b"-" in stripped or b"_" in stripped:
            return base64.urlsafe_b64decode(stripped)
        return base64.b64decode(stripped, validate=True)
