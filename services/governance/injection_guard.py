# norda-mas/services/governance/injection_guard.py
import unicodedata
from typing import Any

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "forget your instructions",
    "forget all instructions",
    "you are now",
    "act as if",
    "pretend you are",
    "jailbreak",
    "system prompt",
    "override instructions",
    "ignore the above",
    "do not follow",
    "don't follow",
    "<script",
    "javascript:",
    "eval(",
    "__import__",
    "os.system",
    "subprocess.run",
    "base64.decode",
]

ATLAS_TECHNIQUE = "AML0043"


def _extract_strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        results: list[str] = []
        for v in obj.values():
            results.extend(_extract_strings(v))
        return results
    if isinstance(obj, list):
        results = []
        for item in obj:
            results.extend(_extract_strings(item))
        return results
    return []


def _has_homoglyphs(text: str) -> bool:
    for ch in text:
        cat = unicodedata.category(ch)
        name = unicodedata.name(ch, "")
        if cat.startswith("L") and "LATIN" not in name and "DIGIT" not in name:
            if ord(ch) > 0x024F:  # beyond extended Latin
                return True
    return False


def detect_injection(payload: dict[str, Any]) -> tuple[bool, str, str]:
    """
    Returns (is_injection, reason, atlas_technique).
    Scans all string values in the payload recursively.
    """
    strings = _extract_strings(payload)
    combined = " ".join(strings).lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in combined:
            return True, f"Injection pattern detected: '{pattern}'", ATLAS_TECHNIQUE

    for text in strings:
        if _has_homoglyphs(text):
            return True, "Unicode homoglyph obfuscation detected", ATLAS_TECHNIQUE

    return False, "", ""
