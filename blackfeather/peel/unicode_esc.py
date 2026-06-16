import re
from typing import Optional

from .base import BaseDecoder, DecodeResult


_UNICODE_ESC_RE = re.compile(rb"\\u[0-9a-fA-F]{4}")


class UnicodeEscDecoder(BaseDecoder):
    name = "Unicode Escape"
    priority = 35

    def detect(self, data: bytes) -> bool:
        if not data:
            return False
        try:
            data.decode("ascii")
        except UnicodeDecodeError:
            return False
        return bool(_UNICODE_ESC_RE.search(data))

    def decode(self, data: bytes) -> bytes:
        text = data.decode("ascii")

        def replace_escape(m):
            return chr(int(m.group(1), 16))

        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", replace_escape, text)
        return decoded.encode("utf-8")
