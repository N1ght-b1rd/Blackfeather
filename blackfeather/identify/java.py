"""
Magic: 0xACED (STREAM_MAGIC) + 0x0005 (STREAM_VERSION).
"""
import struct
from typing import Optional

from .base import BaseDetector, MatchResult
from ..config import CONFIDENCE_EXACT_MAGIC


# Constantes do protocolo de stream do Java
STREAM_MAGIC = 0xACED
STREAM_VERSION = 5

# Type codes que aparecem no stream
TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_PROXYCLASSDESC = 0x7D
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_LONGSTRING = 0x7C
TC_ARRAY = 0x75
TC_ENDBLOCKDATA = 0x78
TC_BLOCKDATA = 0x77
TC_RESET = 0x79


class JavaDetector(BaseDetector):
    name = "Java Serialization"

    @property
    def is_deserialization_format(self) -> bool:
        return True

    def detect(self, data: bytes) -> Optional[MatchResult]:
        if len(data) < 4:
            return None

        # Le os 2 primeiros bytes como STREAM_MAGIC (uint16 big-endian)
        magic = struct.unpack(">H", data[0:2])[0]
        if magic != STREAM_MAGIC:
            return None

        # Le os 2 bytes seguintes como STREAM_VERSION
        version = struct.unpack(">H", data[2:4])[0]
        if version != STREAM_VERSION:
            return None

        magic_hex = f"0x{data[0]:02x}{data[1]:02x}{data[2]:02x}{data[3]:02x}"

        # Tenta extrair nomes de classes do stream
        class_names = self._extract_class_names(data)

        # Detecta libraries pelos nomes das classes
        library_hints = self._detect_libraries(class_names)

        return MatchResult(
            format_name=self.name,
            confidence=CONFIDENCE_EXACT_MAGIC,
            magic_bytes=magic_hex,
            class_names=class_names,
            library_hints=library_hints,
            metadata={"stream_version": version},
        )

    def _extract_class_names(self, data: bytes, max_names: int = 10) -> list:
        """
        Percorre o stream procurando blocos TC_CLASSDESC / TC_OBJECT.
        Pra cada um, lê o nome UTF da classe que vem logo depois.
        """
        names = []
        i = 4  # pula o header (magic + version)
        n = len(data)

        while i < n - 3 and len(names) < max_names:
            token = data[i]
            i += 1

            if token == TC_CLASSDESC or token == TC_PROXYCLASSDESC:
                # Le o comprimento do nome (2 bytes, unsigned)
                if i + 2 > n:
                    break
                name_len = struct.unpack(">H", data[i:i+2])[0]
                i += 2
                # Le os bytes do nome
                if i + name_len > n:
                    break
                try:
                    name = data[i:i+name_len].decode("utf-8", errors="ignore")
                    names.append(name)
                except UnicodeDecodeError:
                    pass
                # Pula o resto do classdesc
                break  # só pega a primeira classe top-level

        return names

    def _detect_libraries(self, class_names: list) -> list:
        
        if not class_names:
            return []

        # Substring -> nome legível da lib
        patterns = {
            "org.apache.commons.collections": "Apache Commons Collections",
            "org.apache.commons.beanutils": "Apache Commons BeanUtils",
            "org.apache.commons.configuration": "Apache Commons Configuration",
            "org.apache.shiro": "Apache Shiro",
            "org.springframework": "Spring Framework",
            "com.fasterxml.jackson": "Jackson",
            "com.alibaba.fastjson": "FastJSON",
            "org.apache.log4j": "Log4j",
            "java.util": "JDK (java.util.*)",
        }

        detected = set()
        for cls in class_names:
            for pattern, lib_name in patterns.items():
                if pattern in cls:
                    detected.add(lib_name)

        return sorted(detected)
