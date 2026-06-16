from pathlib import Path
from typing import Final


PROJECT_ROOT: Final[Path] = Path(__file__).parent.parent
TOOLS_DIR: Final[Path] = PROJECT_ROOT / "tools"


YSOSERIAL_VERSION: Final[str] = "0.0.6"
PHPGGC_VERSION: Final[str] = "1.6.0"


YSOSERIAL_JAR: Final[Path] = TOOLS_DIR / "ysoserial-all.jar"
PHPGGC_PATH: Final[Path] = TOOLS_DIR / "phpggc" / "phpggc"


MAX_PEEL_DEPTH: Final[int] = 10  
MIN_DECODE_SIZE_DELTA: Final[int] = 1  

# Níveis de confiança usados nos matches (0 a 100)
CONFIDENCE_EXACT_MAGIC: Final[int] = 99
CONFIDENCE_STRONG_REGEX: Final[int] = 85
CONFIDENCE_WEAK_REGEX: Final[int] = 65
CONFIDENCE_ENTROPY_HEURISTIC: Final[int] = 50
