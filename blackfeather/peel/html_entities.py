import html
import re
from typing import Optional

from .base import BaseDecoder, DecodeResult


_HTML_ENTITY_RE = re.compile(rb"&(#x?[0-9a-fA-F]+|[A-Za-z]{2,10});")


class HtmlEntitiesDecoder(BaseDecoder):
    name = "HTML Entities"
    priority = 30

    def detect(self, data: bytes) -> bool:
        if not data:
            return False
        try:
            data.decode("ascii")
        except UnicodeDecodeError:
            return False
        return bool(_HTML_ENTITY_RE.search(data))

    def decode(self, data: bytes) -> bytes:
        decoded = html.unescape(data.decode("ascii"))
        return decoded.encode("utf-8")
