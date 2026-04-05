from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class PiiResult:
    detected: bool
    entities: List[str]
    redacted_text: str
    score: float


def detect_and_redact(text: str) -> PiiResult:
    """
    Uses Microsoft Presidio if available; otherwise falls back to a minimal regex-based detector.
    """
    t = text or ""
    try:
        from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
        from presidio_anonymizer import AnonymizerEngine

        # --- Custom Recognizers for India-specific PII ---
        aadhaar_pattern = Pattern(name="aadhaar_pattern", regex=r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", score=0.85)
        aadhaar_recognizer = PatternRecognizer(supported_entity="AADHAAR_NUMBER", patterns=[aadhaar_pattern])

        pan_pattern = Pattern(name="pan_pattern", regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", score=0.85)
        pan_recognizer = PatternRecognizer(supported_entity="PAN_ID", patterns=[pan_pattern])

        analyzer = AnalyzerEngine()
        analyzer.registry.add_recognizer(aadhaar_recognizer)
        analyzer.registry.add_recognizer(pan_recognizer)

        anonymizer = AnonymizerEngine()

        results = analyzer.analyze(text=t, language="en")
        entities = sorted({r.entity_type for r in results})
        if not results:
            return PiiResult(detected=False, entities=[], redacted_text=t, score=0.0)

        anonymized = anonymizer.anonymize(text=t, analyzer_results=results)
        # score: cap to keep risk composition stable
        score = min(0.60, 0.10 + 0.05 * len(results))
        return PiiResult(detected=True, entities=entities, redacted_text=anonymized.text, score=score)
    except Exception:
        # Fallback: conservative redaction for basic patterns
        import re

        email = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
        # Catch standardized formats AND raw 10-digit sequences
        phone = re.compile(r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b|\b\d{10}\b")

        entities: List[str] = []
        redacted = t
        if email.search(redacted):
            entities.append("EMAIL_ADDRESS")
            redacted = email.sub("[REDACTED]", redacted)
        if phone.search(redacted):
            entities.append("PHONE_NUMBER")
            redacted = phone.sub("[REDACTED]", redacted)

        detected = len(entities) > 0
        return PiiResult(detected=detected, entities=entities, redacted_text=redacted, score=0.25 if detected else 0.0)

