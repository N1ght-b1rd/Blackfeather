from dataclasses import dataclass, field
from typing import Optional

from .peel.engine import PeelResult
from .identify.base import MatchResult


@dataclass
class GenerateSuggestion:

    format: str
    chain: str
    rationale: str
    command: str

    def __repr__(self) -> str:
        return f"blackfeather generate {self.format}:{self.chain} --cmd \"<seu_cmd>\"  # {self.rationale}"



_CHAIN_SUGGESTIONS = {
    ("Java Serialization", "Apache Commons Collections"): (
        "CommonsCollections6",
        "Works on JDK 8u71+; most reliable CC chain right now",
    ),
    ("Java Serialization", "Apache Commons BeanUtils"): (
        "CommonsBeanUtils1",
        "Targets TemplatesImpl; works without CC",
    ),
    ("Java Serialization", "Apache Shiro"): (
        "CommonsCollections6",
        "Shiro + CC is the classic combo",
    ),
    ("Java Serialization", "Spring Framework"): (
        "Jdk7u21",
        "Spring usually ships with JDK-only chains",
    ),
    ("Java Serialization", None): (
        "URLDNS",
        "Test if deserialization fires (DNS only, no RCE)",
    ),
    ("Python Pickle", None): (
        "pickle",
        "Native pickle RCE; use subprocess or os.system",
    ),
    ("PHP Serialization", None): (
        "Laravel/RCE",
        "Start with Laravel; phpggc has the full catalog",
    ),
    ("Ruby Marshal", None): (
        "ERB",
        "Native ERB gadget via Open3 or Kernel#open",
    ),
    (".NET BinaryFormatter", None): (
        "TextFormattingRunProperties",
        "Standard .NET RCE chain",
    ),
}


def build_suggestion(match: MatchResult) -> Optional[GenerateSuggestion]:
    
    lib_hint = match.library_hints[0] if match.library_hints else None
    key = (match.format_name, lib_hint)
    if key not in _CHAIN_SUGGESTIONS:
        # Se não tem lib inferida, tenta a versão genérica
        key = (match.format_name, None)

    chain, rationale = _CHAIN_SUGGESTIONS.get(key, (None, None))
    if chain is None:
        return None

    fmt_slug = {
        "Java Serialization": "java",
        "Python Pickle": "python",
        "PHP Serialization": "php",
        "Ruby Marshal": "ruby",
        ".NET BinaryFormatter": "dotnet",
    }.get(match.format_name)

    if fmt_slug is None:
        return None

    command = f"blackfeather generate {fmt_slug}:{chain} --cmd \"id\""
    return GenerateSuggestion(
        format=match.format_name,
        chain=chain,
        rationale=rationale,
        command=command,
    )


@dataclass
class AnalysisReport:

    peel_result: PeelResult
    match_result: Optional[MatchResult]
    suggestion: Optional[GenerateSuggestion]
    input_size: int

    @property
    def has_match(self) -> bool:
        return self.match_result is not None
