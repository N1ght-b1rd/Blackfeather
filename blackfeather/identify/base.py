"""
Classe base pros detectores de formato.

Cada detector testa se os bytes são de um formato conhecido
(Java serialization, PHP, pickle Python, tipo de arquivo, etc).
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MatchResult:
    """Resultado de um match de formato."""

    format_name: str                # ex: "Java Serialization"
    confidence: int                 # 0 a 100
    magic_bytes: Optional[str] = None       # ex: "0xaced0005"
    encoding: Optional[str] = None          # ex: "gzip"
    class_names: list = field(default_factory=list)  # classes Java achadas
    library_hints: list = field(default_factory=list) # libs inferidas (ex: "Apache Commons Collections")
    metadata: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"MatchResult({self.format_name}, confiança={self.confidence}%)"


class BaseDetector(ABC):
    """Base abstrata pros detectores de formato."""

    name: str = "Desconhecido"

    @abstractmethod
    def detect(self, data: bytes) -> Optional[MatchResult]:
        """
        Tenta identificar esse formato nos bytes passados.
        Retorna None se não bateu, ou MatchResult com a confiança.
        """
        ...

    @property
    @abstractmethod
    def is_deserialization_format(self) -> bool:
        """True se o formato é explorável por desserialização."""
        ...
