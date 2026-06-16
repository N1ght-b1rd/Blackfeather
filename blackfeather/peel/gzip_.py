"""
Magic Bytes: 0x1F8B. Decodifica via gzip.decompress.
"""
import gzip
from typing import Optional

from .base import BaseDecoder, DecodeResult


class GzipDecoder(BaseDecoder):
    name = "Gzip"
    priority = 90 

    def detect(self, data: bytes) -> bool:
        return len(data) >= 2 and data[0:2] == b"\x1f\x8b"

    def decode(self, data: bytes) -> bytes:
        return gzip.decompress(data)
