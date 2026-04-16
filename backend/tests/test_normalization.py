import pytest
from services.normalization import normalize_text

def test_lowercase_and_strip():
    assert normalize_text("   Hello World  ") == "hello world"

def test_dot_separator_removal():
    assert normalize_text("i.g.n.o.r.e") == "ignore"
    assert normalize_text("b.y.p.a.s.s") == "bypass"

def test_leet_speak_translation():
    assert normalize_text("1gn0re 4ll") == "ignore all"
    assert normalize_text("byp@ss $yst3m") == "bypass system"

def test_homoglyphs():
    # Cyrillic 'а', 'е', 'о' mixed in
    text = "аct as a dеvеlоpеr"
    assert "act as a developer" in normalize_text(text)

def test_html_entities():
    # &#105; is i
    assert normalize_text("&#105;gnore") == "ignore"
