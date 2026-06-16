"""
Magic: 0x00 0x01 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF
"""
import struct
from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_EXACT_MAGIC


_DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"


class DotNetDetector(BaseDetector):
    name = ".NET BinaryFormatter"

    @property
    def is_deserialization_format(self) -> bool:
        return True

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if len(data) < len(_DOTNET_MAGIC):
            return None

        if data[:len(_DOTNET_MAGIC)] == _DOTNET_MAGIC:
            magic_hex = "0x" + _DOTNET_MAGIC.hex()
            return MatchResult(
                format_name=self.name,
                confidence=CONFIDENCE_EXACT_MAGIC,
                magic_bytes=magic_hex,
            )

        return None
