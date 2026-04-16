import re
import unicodedata


# ── invisible / zero-width characters ────────────────────────────────────────
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\u2062-\u2064\ufeff\u00ad]")

# ── repeated punctuation used as visual separators  (e.g. i.g.n.o.r.e) ──────
_DOT_SEPARATED = re.compile(r"(?<=[a-z0-9])\.(?=[a-z0-9])")

# ── collapse runs of whitespace / newlines ────────────────────────────────────
_MULTI_SPACE = re.compile(r"\s+")

# ── HTML / URL encode remnants that slip through (&#105; = 'i', %69 = 'i') ───
_HTML_ENTITY = re.compile(r"&#(\d+);")
_URL_ENCODE  = re.compile(r"%([0-9a-fA-F]{2})")

# ── Unicode homoglyph map: visually identical characters → ASCII ──────────────
# Covers Cyrillic, Greek, and common lookalikes used in adversarial prompts
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Common Unicode lookalikes
    "𝐢": "i", "𝐈": "i", "𝗶": "i", "𝘪": "i", "𝙞": "i",
    "ℹ": "i", "¡": "i",
    "ℓ": "l", "ⅼ": "l",
    "℃": "c",
    "𝟎": "0", "𝟏": "1", "𝟐": "2",
    # Fullwidth ASCII (！ＡＢＣ...)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}

# ── Leetspeak / substitution cipher map ──────────────────────────────────────
# Applied AFTER homoglyph resolution so multi-pass obfuscation is caught.
_LEET: dict[str, str] = {
    "0": "o",
    "1": "i",   # covers both  l  and  i  targets
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "i",
    "+": "t",
    "(": "c",
}


def _replace_html_entities(text: str) -> str:
    def sub_html(m: re.Match) -> str:
        try:
            return chr(int(m.group(1)))
        except (ValueError, OverflowError):
            return m.group(0)
    return _HTML_ENTITY.sub(sub_html, text)


def _replace_url_encoding(text: str) -> str:
    def sub_url(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return _URL_ENCODE.sub(sub_url, text)


def _resolve_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _apply_leet(text: str) -> str:
    return "".join(_LEET.get(ch, ch) for ch in text)


def _normalize_unicode(text: str) -> str:
    """NFKC decomposition collapses ligatures, superscripts, fractions, etc."""
    return unicodedata.normalize("NFKC", text)


def normalize_text(text: str) -> str:
    """
    Multi-pass adversarial-input normalization pipeline.

    Order matters — each pass feeds into the next:
      1. NFKC unicode normalization   (ligatures, superscripts, fractions)
      2. Homoglyph resolution         (Cyrillic/Greek lookalikes → ASCII)
      3. HTML entity decoding         (&#105; → i)
      4. URL percent-decoding         (%69 → i)
      5. Zero-width / invisible chars stripped
      6. Lowercase
      7. Dot-separator removal        (i.g.n.o.r.e → ignore)
      8. Leet / substitution cipher   (1gn0r3 → ignore)
      9. Collapse whitespace
    """
    if not text:
        return ""

    t = text.strip()
    t = _normalize_unicode(t)
    t = _resolve_homoglyphs(t)
    t = _replace_html_entities(t)
    t = _replace_url_encoding(t)
    t = _ZERO_WIDTH.sub("", t)
    t = t.lower()
    t = _DOT_SEPARATED.sub("", t)   # i.g.n.o.r.e → ignore
    t = _apply_leet(t)
    t = _MULTI_SPACE.sub(" ", t)
    return t.strip()