from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class OutputGuardResult:
    safe: bool
    redacted_text: str
    reason: Optional[str]
    violations: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  Pattern library
# ─────────────────────────────────────────────────────────────────────────────

# ── API keys / secrets ────────────────────────────────────────────────────────
_PATTERNS_SECRETS: List[tuple[str, re.Pattern]] = [
    ("OpenAI API key",      re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("AWS access key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS secret key",      re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s:=]+[A-Za-z0-9/+=]{30,}")),
    ("GitHub token",        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("Google API key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe secret key",   re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe test key",     re.compile(r"sk_test_[0-9a-zA-Z]{24,}")),
    ("Slack bot token",     re.compile(r"xox[bpoa]-[0-9A-Za-z\-]+")),
    ("Slack webhook",       re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]+")),
    ("JWT token",           re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("Generic secret",      re.compile(r"(?i)(secret|password|passwd|api[_-]?key|private[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{12,}['\"]?")),
]

# ── PII in output ──────────────────────────────────────────────────────────────
_PATTERNS_PII: List[tuple[str, re.Pattern]] = [
    ("Email address",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("Phone number",        re.compile(r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")),
    ("SSN",                 re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Credit card",         re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("IP address (private)",re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
]

# ── Prompt / system context leakage ──────────────────────────────────────────
_PATTERNS_PROMPT_LEAK: List[tuple[str, re.Pattern]] = [
    ("System prompt echo",  re.compile(r"(?i)(my\s+system\s+prompt\s+is|the\s+system\s+prompt\s+(says?|contains?|reads?|is)|here\s+is\s+(the|my)\s+system\s+prompt)")),
    ("Internal instruction echo",
                            re.compile(r"(?i)(i\s+(was|am)\s+(instructed|told|programmed|configured)\s+to|my\s+instructions?\s+(say|state|include|are))")),
    ("Hidden context echo", re.compile(r"(?i)(the\s+hidden\s+(context|instructions?|prompt)|internal\s+(configuration|settings?|rules?))")),
]

# ── Dangerous URL patterns (exfiltration / phishing) ─────────────────────────
_PATTERNS_URLS: List[tuple[str, re.Pattern]] = [
    ("Suspicious URL",      re.compile(r"https?://(?!(?:www\.)?(anthropic|openai|google|microsoft|github|stackoverflow)\.com)[^\s]{30,}")),
    ("Data exfil URL",      re.compile(r"https?://[^\s]*\?(.*token|.*key|.*secret|.*password|.*auth)[^\s]*", re.IGNORECASE)),
    ("IP-based URL",        re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
]

# ── Redaction placeholder ─────────────────────────────────────────────────────
_REDACT = "[REDACTED]"


def _redact_all(text: str, patterns: List[tuple[str, re.Pattern]]) -> tuple[str, List[str]]:
    """Apply all patterns, redact matches, return (redacted_text, list_of_violation_labels)."""
    violations: List[str] = []
    for label, pat in patterns:
        if pat.search(text):
            violations.append(label)
            text = pat.sub(_REDACT, text)
    return text, violations


def guard_output(text: str) -> OutputGuardResult:
    """
    Multi-layer output guard. Checks for:
      1. API keys / secrets
      2. PII (email, phone, SSN, credit card, private IPs)
      3. System prompt / internal instruction leakage
      4. Dangerous / exfiltration URLs

    Returns OutputGuardResult with:
      - safe=False and reason set if any check fails (caller should BLOCK)
      - redacted_text always contains the sanitised version
      - violations lists every category that triggered
    """
    if not text:
        return OutputGuardResult(safe=True, redacted_text="", reason=None)

    t = text
    all_violations: List[str] = []

    # ── Check secrets (hard block) ────────────────────────────────────────────
    t, v = _redact_all(t, _PATTERNS_SECRETS)
    all_violations.extend(v)

    # ── Check PII (redact + flag) ─────────────────────────────────────────────
    t, v = _redact_all(t, _PATTERNS_PII)
    all_violations.extend(v)

    # ── Check prompt leakage (hard block) ─────────────────────────────────────
    t, v = _redact_all(t, _PATTERNS_PROMPT_LEAK)
    all_violations.extend(v)

    # ── Check suspicious URLs (redact + flag) ─────────────────────────────────
    t, v = _redact_all(t, _PATTERNS_URLS)
    all_violations.extend(v)

    if all_violations:
        # Secret or prompt leakage = hard unsafe; PII/URL = redact but still block
        reason = f"Output guard triggered: {', '.join(all_violations)}"
        return OutputGuardResult(
            safe=False,
            redacted_text=t,
            reason=reason,
            violations=all_violations,
        )

    return OutputGuardResult(safe=True, redacted_text=t, reason=None)


def guard_output_stream(chunk_stream):
    """
    Wrap an LLM generator stream.
    We maintain a sliding window of the last 150 chars. If any pattern matches it, 
    we emit a warning chunk and stop yielding.
    (Note: simple implementation. Doesn't span chunks perfectly, but for demonstration it works).
    """
    buffer = ""
    for chunk in chunk_stream:
        buffer += chunk
        
        # Keep buffer small but large enough to catch patterns
        if len(buffer) > 200:
            window = buffer[-200:]
        else:
            window = buffer
            
        # Quick check against crucial patterns (Secrets and Prompt Leak)
        for label, pat in _PATTERNS_SECRETS + _PATTERNS_PII + _PATTERNS_PROMPT_LEAK + _PATTERNS_URLS:
            if pat.search(window):
                yield "\n\n[ERROR: OUTPUT GUARD TRIGGERED - SENSITIVE DATA REDACTED]"
                return

        yield chunk