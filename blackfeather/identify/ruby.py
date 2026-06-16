"""
Magic: 0x04 0x08
"""
import struct
from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_EXACT_MAGIC


RUBY_MARSHAL_VERSION_MAJOR = 4
RUBY_MARSHAL_VERSION_MINOR = 8


class RubyDetector(BaseDetector):
    name = "Ruby Marshal"

    @property
    def is_deserialization_format(self) -> bool:
        return True

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if len(data) < 2:
            return None

        major = data[0]
        minor = data[1]
        if major != RUBY_MARSHAL_VERSION_MAJOR or minor != RUBY_MARSHAL_VERSION_MINOR:
            return None

        magic_hex = f"0x{data[0]:02x}{data[1]:02x}"
        return MatchResult(
            format_name=self.name,
            confidence=CONFIDENCE_EXACT_MAGIC,
            magic_bytes=magic_hex,
            metadata={"marshal_version": f"{major}.{minor}"},
        )
