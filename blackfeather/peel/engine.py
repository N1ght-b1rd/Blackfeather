"""
Recebe bytes, testa cada decoder, decodifica e joga o resultado
de volta no loop até:
  - Nenhum decoder bater
  - bater em um hash (MD5, SHA, etc)
  - Atingir MAX_PEEL_DEPTH
  - O decode não reduzir o tamanho (loop infinito)

Devolve o PeelResult com os bytes finais e o pipeline.
"""
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import MAX_PEEL_DEPTH
from .base import BaseDecoder, DecodeResult
from .base64 import Base64Decoder
from .hex import HexDecoder
from .gzip_ import GzipDecoder
from .url import UrlDecoder
from .html_entities import HtmlEntitiesDecoder
from .unicode_esc import UnicodeEscDecoder
from .hash import HashDetector


@dataclass
class PipelineStep:

    encoder: str
    size_before: int
    size_after: int
    is_one_way: bool = False

    def __repr__(self) -> str:
        if self.is_one_way:
            return f"{self.encoder} [one-way, parou aqui]"
        return f"{self.encoder}: {self.size_before} -> {self.size_after} bytes"


@dataclass
class PeelResult:

    raw_data: bytes                         
    pipeline: List[PipelineStep] = field(default_factory=list)  
    stopped_at_one_way: bool = False        
    stopped_at_max_depth: bool = False      
    final_size: int = 0

    def add_step(self, step: PipelineStep) -> None:
        self.pipeline.append(step)

    @property
    def is_raw(self) -> bool:
        """True se nenhum decoder bateu (input já era raw)."""
        return len(self.pipeline) == 0


# Ordem de prioridade dos decoders
DEFAULT_DECODERS: List[BaseDecoder] = [
    HashDetector(),         # 100
    GzipDecoder(),          # 90
    HexDecoder(),           # 80
    Base64Decoder(),        # 60
    UrlDecoder(),           # 40
    UnicodeEscDecoder(),    # 35
    HtmlEntitiesDecoder(),  # 30
]


class PeelEngine:
    """
    Pega bytes de entrada, descasca as camadas de encoding recursivamente
    e devolve os bytes raw + o registro de cada passo.
    """

    def __init__(self, decoders: Optional[List[BaseDecoder]] = None):
        
        self.decoders = sorted(
            decoders if decoders is not None else DEFAULT_DECODERS,
            key=lambda d: d.priority,
            reverse=True,
        )

    def peel(self, data: bytes) -> PeelResult:

        result = PeelResult(raw_data=data, final_size=len(data))
        current = data
        prev_decoder: Optional[str] = None
        prev_output: Optional[bytes] = None

        for depth in range(MAX_PEEL_DEPTH):
            matched_decoder: Optional[BaseDecoder] = None
            matched_result: Optional[DecodeResult] = None

            # Tenta cada decoder na ordem de prioridade
            for decoder in self.decoders:
                outcome = decoder.try_decode(current)
                if outcome is not None:
                    matched_decoder = decoder
                    matched_result = outcome
                    break

            # Nenhum bateu: raw
            if matched_decoder is None or matched_result is None:
                break


            is_one_way = matched_result.__dict__.get("is_one_way", False)
            if is_one_way:
                result.add_step(PipelineStep(
                    encoder=matched_result.encoder_name,
                    size_before=matched_result.original_size,
                    size_after=matched_result.decoded_size,
                    is_one_way=True,
                ))
                result.stopped_at_one_way = True
                # No caso de hash, raw_data é o próprio hash (não tem o que decodificar)
                result.raw_data = current
                result.final_size = len(current)
                return result

            # Detecta loop infinito real: mesmo decoder + mesmo output da iteracao anterior
            # (gzip em pickle pequena EXPANDE bytes, isso nao e loop, e sinal normal de compressor)
            if (
                prev_decoder is not None
                and matched_decoder.name == prev_decoder
                and matched_result.data == prev_output
            ):
                result.stopped_at_max_depth = True
                result.raw_data = current
                result.final_size = len(current)
                return result

            result.add_step(PipelineStep(
                encoder=matched_result.encoder_name,
                size_before=matched_result.original_size,
                size_after=matched_result.decoded_size,
                is_one_way=False,
            ))

            prev_decoder = matched_decoder.name
            prev_output = matched_result.data
            current = matched_result.data
            result.raw_data = current
            result.final_size = len(current)

        if len(result.pipeline) >= MAX_PEEL_DEPTH:
            result.stopped_at_max_depth = True

        return result
