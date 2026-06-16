from abc import ABC, abstractmethod
from typing import Optional


class DecodeResult:

    def __init__(self, data: bytes, encoder_name: str, original_size: int):
        self.data = data
        self.encoder_name = encoder_name
        self.original_size = original_size
        self.decoded_size = len(data)
        self.size_delta = original_size - len(data)

    def __repr__(self) -> str:
        return f"DecodeResult({self.encoder_name}, {self.original_size} -> {self.decoded_size} bytes)"


class BaseDecoder(ABC):
    
    name: str = "Desconhecido"

    # Quanto mais perto de 0, antes o decoder é testado.
    # Sim, isso eh uma gambiarra pra evitar falsos positivos de matches mais genericos como b64.
    priority: int = 50

    @abstractmethod
    def detect(self, data: bytes) -> bool:
        
        ...

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        
        ...

    def try_decode(self, data: bytes) -> Optional[DecodeResult]:
        
        if not self.detect(data):
            return None
        try:
            decoded = self.decode(data)
            return DecodeResult(decoded, self.name, len(data))
        except (ValueError, Exception):
            return None
