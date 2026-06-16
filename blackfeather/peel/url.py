import re
import urllib.parse
from typing import Optional

from .base import BaseDecoder, DecodeResult


_URL_ENCODED_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


class UrlDecoder(BaseDecoder):
    name = "URL"
    priority = 40

    def detect(self, data: bytes) -> bool:
        if not data:
            return False
        
        try:
            data.decode("ascii")
        except UnicodeDecodeError:
            return False
        
        return bool(_URL_ENCODED_RE.search(data))

    def decode(self, data: bytes) -> bytes:
        decoded = urllib.parse.unquote(data.decode("ascii"))
        return decoded.encode("ascii")
