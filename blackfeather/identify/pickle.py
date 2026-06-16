"""
Magic numbers:
  Protocolo 0/1 (texto): começa com (dp0\\n, cos\\n, (S', etc
  Protocolo 2-5 (binário): começa com \\x80 seguido do número do protocolo
    - 0x80 0x02 -> protocolo 2
    - 0x80 0x03 -> protocolo 3
    - 0x80 0x04 -> protocolo 4 (default do Python 3.8+)
    - 0x80 0x05 -> protocolo 5 (Python 3.8+)
"""
import re
from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_EXACT_MAGIC


# Protocolos binários: \x80 + byte do protocolo
_PICKLE_BINARY_RE = re.compile(rb"^\x80[\x02-\x05]")

# Protocolos texto (0, 1): ASCII começando com opcodes do pickle
# Exemplos comuns: (dp0, cos, (S', (S", (c, ((, l, etc
_PICKLE_TEXT_RE = re.compile(rb"^(\(dp0|cos|\(S'|\(S\"|\(|c[A-Za-z_])")


class PickleDetector(BaseDetector):
    name = "Python Pickle"

    @property
    def is_deserialization_format(self) -> bool:
        return True

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if not data:
            return None

        # Protocolo binário
        m = _PICKLE_BINARY_RE.match(data)
        if m:
            protocol = data[1]
            magic_hex = f"0x{data[0]:02x}{data[1]:02x}"
            return MatchResult(
                format_name=self.name,
                confidence=CONFIDENCE_EXACT_MAGIC,
                magic_bytes=magic_hex,
                metadata={"pickle_protocol": protocol},
            )

        # Protocolo texto
        if _PICKLE_TEXT_RE.match(data):
            return MatchResult(
                format_name=self.name,
                confidence=CONFIDENCE_EXACT_MAGIC - 5,  # 94% pra protocolo texto
                metadata={"pickle_protocol": 0},
            )

        return None
