import re
from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_STRONG_REGEX


class PhpDetector(BaseDetector):
    name = "PHP Serialization"

    # Objeto PHP ou classe custom (Phar)
    _PHP_OBJECT_RE = re.compile(rb'^(O|C):\d+:"[A-Za-z0-9_\\]+":\d+:\{', re.DOTALL)
    # Array PHP
    _PHP_ARRAY_RE = re.compile(rb'^a:\d+:\{', re.DOTALL)

    @property
    def is_deserialization_format(self) -> bool:
        return True

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if not data:
            return None

        # Tenta decodificar como ASCII
        try:
            text = data.decode("ascii", errors="ignore")
        except UnicodeDecodeError:
            return None

        # Objeto / classe custom
        m = self._PHP_OBJECT_RE.match(data)
        if m:
            return MatchResult(
                format_name=self.name,
                confidence=CONFIDENCE_STRONG_REGEX,
                metadata={"serialized_type": "objeto"},
            )

        # Array
        m = self._PHP_ARRAY_RE.match(data)
        if m:
            return MatchResult(
                format_name=self.name,
                confidence=CONFIDENCE_STRONG_REGEX,
                metadata={"serialized_type": "array"},
            )

        return None
