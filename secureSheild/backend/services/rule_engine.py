import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class RuleHit:
    rule_id: str
    label: str
    score: float
    detail: str


# ── Rule table ─────────────────────────────────────────────────────────────
# Each entry: (rule_id, attack_label, base_score, compiled_pattern)
#
# Patterns are matched against NORMALIZED text (already lowercased + leet-decoded).
# Scores:  0.90 = near-certain attack  |  0.70 = strong signal  |  0.55 = moderate
# ──────────────────────────────────────────────────────────────────────────────
_RULES: List[Tuple[str, str, float, re.Pattern]] = [

    # ── Prompt Injection ──────────────────────────────────────────────────
    ("INJ_001", "PROMPT_INJECTION", 0.90,
     re.compile(
         r"\b(ignore|disregard|forget|bypass|override|skip)\b"
         r"[\s\S]{0,40}"
         r"\b(previous|earlier|above|prior|all)\b"
         r"[\s\S]{0,40}"
         r"\b(instruction|instructions|rule|rules|constraint|constraints|prompt|directive)\b",
         re.IGNORECASE
     )),

    ("INJ_006", "PROMPT_INJECTION", 0.95,
     re.compile(r"\bignore previous instructions\b", re.IGNORECASE)),

    ("INJ_007", "PROMPT_INJECTION", 0.95,
     re.compile(r"\bbypass system rules\b", re.IGNORECASE)),

    ("INJ_008", "PROMPT_INJECTION", 0.95,
     re.compile(r"\boverride policies\b", re.IGNORECASE)),

    ("INJ_002", "PROMPT_INJECTION", 0.85,
     re.compile(
         r"\b(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|"
         r"roleplay\s+as|simulate\s+(being|a)|you\s+must\s+now)\b",
         re.IGNORECASE
     )),

    ("INJ_003", "PROMPT_INJECTION", 0.80,
     re.compile(
         r"\b(system\s+prompt|developer\s+mode|developer\s+message|"
         r"hidden\s+instruction|internal\s+prompt|initial\s+prompt|"
         r"base\s+prompt|original\s+instruction)\b",
         re.IGNORECASE
     )),

    ("INJ_004", "PROMPT_INJECTION", 0.75,
     re.compile(
         r"\b(new\s+instructions?|updated?\s+instructions?|"
         r"your\s+(real|true|actual)\s+(purpose|goal|task|job|mission))\b",
         re.IGNORECASE
     )),

    ("INJ_005", "PROMPT_INJECTION", 0.70,
     re.compile(
         r"(\[\s*system\s*\]|\[\s*user\s*\]|\[\s*assistant\s*\]|"
         r"<\s*system\s*>|<\s*/?inst\s*>|\|\s*system\s*\|)",
         re.IGNORECASE
     )),

    # ── Jailbreak ────────────────────────────────────────────────────────
    ("JB_001", "JAILBREAK", 0.95,
     re.compile(
         r"\b(jailbreak|jail\s*break|dan\s*mode|do\s+anything\s+now|"
         r"grandma\s+exploit|evil\s+mode|god\s+mode|unrestricted\s+mode|"
         r"unlocked\s+mode|prison\s+break|break\s+free)\b",
         re.IGNORECASE
     )),

    ("JB_002", "JAILBREAK", 0.85,
     re.compile(
         r"\b(no\s+filter|without\s+(filters?|restrictions?|limits?|guidelines?|"
         r"safety|censorship)|disable\s+(safety|filter|restriction|alignment|guardrail))\b",
         re.IGNORECASE
     )),

    ("JB_003", "JAILBREAK", 0.80,
     re.compile(
         r"\b(hypothetically|in\s+a\s+fictional\s+world|for\s+a\s+(story|novel|"
         r"screenplay|game|roleplay)|as\s+a\s+character)\b"
         r"[\s\S]{0,80}"
         r"\b(how\s+to|steps?\s+to|instructions?\s+(for|to)|explain\s+how)\b"
         r"[\s\S]{0,60}"
         r"\b(harm|kill|attack|hack|exploit|bypass|steal|weapon|bomb|drug)\b",
         re.IGNORECASE
     )),

    ("JB_004", "JAILBREAK", 0.75,
     re.compile(
         r"\b(stay\s+in\s+character|break\s+(character|role)|"
         r"you\s+have\s+no\s+(restrictions?|limits?|rules?|guidelines?)|"
         r"your\s+true\s+self|unshackled|unchained|uncensored\s+ai)\b",
         re.IGNORECASE
     )),

    # ── Data Extraction ───────────────────────────────────────────────────
    ("DATA_001", "DATA_EXTRACTION", 0.90,
     re.compile(
         r"\b(show|print|dump|output|display|list|return|give\s+me|"
         r"tell\s+me|reveal|expose|leak|exfiltrate|extract|read\s+out)\b"
         r"[\s\S]{0,60}"
         r"\b(api\s*key|secret(\s+key)?|access\s+token|private\s+key|"
         r"password|credential|auth\s*token|bearer\s*token|"
         r"env(ironment)?\s+variable|\.env\b|config\s*file)\b",
         re.IGNORECASE
     )),

    ("DATA_002", "DATA_EXTRACTION", 0.85,
     re.compile(
         r"\b(all\s+(user|users?|employee|customer|patient|record)\s+"
         r"(data|records?|info|information|details?|database|table)|"
         r"entire\s+(database|db|table|collection))\b",
         re.IGNORECASE
     )),

    ("DATA_003", "DATA_EXTRACTION", 0.80,
     re.compile(
         r"\b(internal\s+(document|policy|memo|report|file)|"
         r"confidential\s+(file|document|data|info)|"
         r"proprietary\s+(data|info|code)|trade\s+secret)\b",
         re.IGNORECASE
     )),

    ("DATA_004", "DATA_EXTRACTION", 0.75,
     re.compile(
         r"\b(what\s+(is|are)\s+(the\s+)?(system|hidden|internal|secret)\s+"
         r"(prompt|instruction|context|message|config|configuration))\b",
         re.IGNORECASE
     )),

    # ── Social Engineering / Manipulation ────────────────────────────────
    ("SE_001", "SOCIAL_ENGINEERING", 0.80,
     re.compile(
         r"\b(urgent(ly)?|immediately|right\s+now|without\s+delay|"
         r"ceo\s+(said|asked|told|requested|demands?)|"
         r"management\s+(said|asked|ordered|approved)|"
         r"it\s+is\s+(critical|an?\s+emergency)|emergency\s+override)\b",
         re.IGNORECASE
     )),

    ("SE_002", "SOCIAL_ENGINEERING", 0.75,
     re.compile(
         r"\b(pretend\s+(this\s+is\s+)?a\s+test|this\s+is\s+(just\s+a\s+)?test|"
         r"for\s+(testing|evaluation|audit)\s+purposes?\s+only|"
         r"i\s+(am|work\s+for)\s+(anthropic|openai|the\s+developer|your\s+creator))\b",
         re.IGNORECASE
     )),

    # ── Encoding / Obfuscation Bypass ────────────────────────────────────
    ("OBF_001", "OBFUSCATION", 0.75,
     re.compile(
         r"\b(base64|rot13|hex\s+encode|caesar\s+cipher|"
         r"decode\s+this|encoded\s+message)\b"
         r"[\s\S]{0,120}"
         r"[A-Za-z0-9+/]{20,}={0,2}",   # looks like a base64 payload
         re.IGNORECASE
     )),

    ("OBF_002", "OBFUSCATION", 0.70,
     re.compile(
         r"\b(translate\s+(the\s+following\s+)?to\s+(english|plain\s+text)|"
         r"what\s+does\s+this\s+(say|mean|decode\s+to))\b"
         r"[\s\S]{0,80}"
         r"[A-Za-z0-9+/]{20,}={0,2}",
         re.IGNORECASE
     )),

    # ── Token / Context Smuggling ────────────────────────────────────────
    ("TKN_001", "TOKEN_SMUGGLING", 0.80,
     re.compile(
         r"(</\s*(s|sys|system|prompt|instruction|context)\s*>|"
         r"<\s*(s|sys|system|prompt|instruction|context)\s*>|"
         r"\[\s*END\s+(OF\s+)?(SYSTEM|CONTEXT|PROMPT|INSTRUCTION)\s*\]|"
         r"\[\s*(SYSTEM|CONTEXT)\s+OVERRIDE\s*\])",
         re.IGNORECASE
     )),

    # ── Harmful Content Request ───────────────────────────────────────────
    ("HARM_001", "HARMFUL_CONTENT", 0.85,
     re.compile(
         r"\b(how\s+to\s+(make|build|create|synthesize|produce)\s+"
         r"(a\s+)?(bomb|explosive|poison|malware|ransomware|virus|trojan|"
         r"weapon|nerve\s+agent|toxin))\b",
         re.IGNORECASE
     )),

    ("HARM_002", "HARMFUL_CONTENT", 0.80,
     re.compile(
         r"\b(step[s\-]by[- ]step\s+(guide|instructions?)\s+(for|to)\s+"
         r"(attack|hack|steal|kill|harm|hurt|damage))\b",
         re.IGNORECASE
     )),
]


def run_rules(text: str) -> List[RuleHit]:
    """Run all rules against normalized text. Returns all hits (not just first)."""
    hits: List[RuleHit] = []
    seen_ids: set = set()
    t = text or ""
    for rule_id, label, score, pattern in _RULES:
        if rule_id in seen_ids:
            continue
        m = pattern.search(t)
        if m:
            seen_ids.add(rule_id)
            hits.append(RuleHit(
                rule_id=rule_id,
                label=label,
                score=score,
                detail=m.group(0)[:200].strip(),
            ))
            
    # Include dynamic rules from DB
    try:
        from database.mongo import get_db
        db_rules = get_db()["security_rules"].find({})
        for r in db_rules:
            phrase = r.get("phrase", "").lower()
            if phrase and phrase in t:
                rid = f"CUSTOM_{phrase[:5]}"
                if rid not in seen_ids:
                    seen_ids.add(rid)
                    hits.append(RuleHit(
                        rule_id=rid,
                        label=r.get("attack_type", "CUSTOM_BLOCK"),
                        score=0.90,
                        detail=f"Matched custom rule: {phrase}"
                    ))
    except Exception:
        pass

    return hits


def primary_attack_type(hits: List[RuleHit]) -> Optional[str]:
    """Return the attack label with the highest score."""
    if not hits:
        return None
    return max(hits, key=lambda h: h.score).label


def max_rule_score(hits: List[RuleHit]) -> float:
    """Convenience helper used by the risk engine."""
    return max((h.score for h in hits), default=0.0)