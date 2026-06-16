import re
from typing import Optional

from .base import BaseDecoder, DecodeResult


_HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")


class HexDecoder(BaseDecoder):
    name = "Hex"
    priority = 80

    def detect(self, data: bytes) -> bool:
        if not data or len(data) < 4:
            return False
        stripped = data.strip()
        # Hex sempre tem tamanho par (cada byte = 2 chars)
        if len(stripped) % 2 != 0:
            return False
        return bool(_HEX_RE.match(stripped))

    def decode(self, data: bytes) -> bytes:
        return bytes.fromhex(data.strip().decode("ascii"))
