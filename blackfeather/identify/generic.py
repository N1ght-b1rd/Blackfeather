from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_EXACT_MAGIC, CONFIDENCE_STRONG_REGEX


# (magic_bytes, nome do formato, é texto?)
_MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image", False),
    (b"\xff\xd8\xff", "JPEG image", False),
    (b"GIF87a", "GIF image (87a)", False),
    (b"GIF89a", "GIF image (89a)", False),
    (b"%PDF-", "PDF document", False),
    (b"PK\x03\x04", "ZIP archive / JAR / Office", False),
    (b"PK\x05\x06", "ZIP archive (vazio)", False),
    (b"PK\x07\x08", "ZIP archive (spanned)", False),
    (b"\x7fELF", "ELF binary (Linux)", False),
    (b"BM", "BMP image", False),
    (b"\x1f\x8b", "Gzip cru (não veio de outro decoder)", False),
    (b"<?xml", "XML document", True),
    (b"<!DOCTYPE html", "HTML document", True),
    (b"<html", "HTML document", True),
]


class GenericDetector(BaseDetector):
    name = "Assinatura de arquivo"

    @property
    def is_deserialization_format(self) -> bool:
        return False 

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if not data:
            return None

        for magic, fmt_name, is_text in _MAGIC_SIGNATURES:
            if data.startswith(magic):
                
                confidence = CONFIDENCE_STRONG_REGEX if is_text else CONFIDENCE_EXACT_MAGIC
                return MatchResult(
                    format_name=fmt_name,
                    confidence=confidence,
                    magic_bytes="0x" + magic[:4].hex(),
                )

        return None
