"""
Detector de hash one-way (MD5, SHA-1, SHA-256, SHA-512).

"""
import re
from typing import Optional

from .base import BaseDecoder, DecodeResult


class HashDetector(BaseDecoder):
  
    name = "Hash (one-way)"
    priority = 100  # testa primeiro, na frente de tudo

    MD5_LEN = 32
    SHA1_LEN = 40
    SHA256_LEN = 64
    SHA512_LEN = 128

    def detect(self, data: bytes) -> bool:
        if not data:
            return False
        stripped = data.strip()
        
        if not re.match(rb"^[0-9a-fA-F]+$", stripped):
            return False
        
        return len(stripped) in (
            self.MD5_LEN,
            self.SHA1_LEN,
            self.SHA256_LEN,
            self.SHA512_LEN,
        )

    def decode(self, data: bytes) -> bytes:
        
        raise ValueError("Hash é one-way; não dá pra decodificar")

    def try_decode(self, data: bytes) -> Optional[DecodeResult]:
        
        if not self.detect(data):
            return None
        stripped = data.strip()
        length = len(stripped)
        if length == self.MD5_LEN:
            hash_type = "MD5"
        elif length == self.SHA1_LEN:
            hash_type = "SHA-1"
        elif length == self.SHA256_LEN:
            hash_type = "SHA-256"
        elif length == self.SHA512_LEN:
            hash_type = "SHA-512"
        else:
            hash_type = "Desconhecido"
        result = DecodeResult(data, f"Hash ({hash_type}, one-way)", len(data))
        
        result.__dict__["is_one_way"] = True
        result.__dict__["hash_type"] = hash_type
        return result
