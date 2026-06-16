from typing import List, Optional

from .base import BaseDetector, MatchResult
from .java import JavaDetector
from .php import PhpDetector
from .pickle import PickleDetector
from .ruby import RubyDetector
from .dotnet import DotNetDetector
from .generic import GenericDetector


# Ordem importa: detectores mais específicos primeiro
DEFAULT_DETECTORS: List[BaseDetector] = [
    JavaDetector(),
    PickleDetector(),
    RubyDetector(),
    DotNetDetector(),
    PhpDetector(),       
    GenericDetector(),   
]


class IdentifyEngine:

    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS

    def identify(self, data: bytes) -> Optional[MatchResult]:
        
        for detector in self.detectors:
            result = detector.detect(data)
            if result is not None:
                return result
        return None
