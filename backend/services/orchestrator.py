from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol
from dataclasses import dataclass

@dataclass
class TierResult:
    is_allowed: bool
    modified_prompt: str
    risk_contribution: float
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None

class SecurityTier(ABC):
    """Base class for every security tier in the Defense-in-Depth pipeline."""
    
    @abstractmethod
    def execute(self, prompt: str, context: Dict[str, Any]) -> TierResult:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

class SecurityOrchestrator:
    """
    Manages the execution of multiple security tiers.
    Implements a fail-fast mechanism (if a tier returns is_allowed=False).
    """

    def __init__(self):
        self._tiers: List[SecurityTier] = []

    def add_tier(self, tier: SecurityTier):
        self._tiers.append(tier)
        return self

    def run(self, original_prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the pipeline and returns a consolidated security assessment."""
        current_prompt = original_prompt
        total_risk = 0.0
        details = {}
        is_blocked = False
        block_reason = None
        
        tier_results = []

        for tier in self._tiers:
            try:
                result = tier.execute(current_prompt, context)
                tier_results.append({
                    "tier": tier.name,
                    "risk": result.risk_contribution,
                    "allowed": result.is_allowed
                })
                
                details[tier.name] = result.data
                total_risk += result.risk_contribution
                current_prompt = result.modified_prompt
                
                if not result.is_allowed:
                    is_blocked = True
                    block_reason = f"Blocked by {tier.name}"
                    break
                    
            except Exception as e:
                # Log using the new structured logger (we'll import it below)
                from services.logger import logger
                logger.error(f"Tier {tier.name} failed: {str(e)}")
                details[tier.name] = {"error": str(e)}

        return {
            "is_blocked": is_blocked,
            "block_reason": block_reason,
            "final_prompt": current_prompt,
            "total_risk_score": min(1.0, total_risk),
            "tier_details": details,
            "pipeline_summary": tier_results
        }

# --- Concrete Tier Implementations ---

from services.normalization import normalize_text
from services.rule_engine import run_rules, max_rule_score, primary_attack_type
from services.semantic_engine import semantic_scan
from services.llm_classifier import classify_intent
from services.policy_engine import evaluate_policy
from services.pii_detector import detect_and_redact

class NormalizationTier(SecurityTier):
    @property
    def name(self): return "Normalization"
    def execute(self, prompt, context):
        norm = normalize_text(prompt)
        return TierResult(True, norm, 0.0, {"normalized_text": norm})

class RuleEngineTier(SecurityTier):
    @property
    def name(self): return "RuleEngine"
    def execute(self, prompt, context):
        hits = run_rules(prompt)
        score = max_rule_score(hits)
        attack = primary_attack_type(hits)
        # Fail fast if critical rules hit
        allowed = score < 0.90 
        return TierResult(allowed, prompt, score * 0.4, {"score": score, "attack_type": attack})

class LLMClassifierTier(SecurityTier):
    @property
    def name(self): return "IntentClassifier"
    def execute(self, prompt, context):
        # Use context for multi-turn injection check
        history = context.get("history", "")
        aug_prompt = f"HISTORY: {history}\n\nCURRENT: {prompt}" if history else prompt
        
        # Pull scores from previous tiers if available in context
        rule_type = context.get("prev_results", {}).get("RuleEngine", {}).get("attack_type")
        sem_score = context.get("prev_results", {}).get("SemanticEngine", {}).get("score", 0.0)
        
        clf = classify_intent(aug_prompt, rule_attack_type=rule_type, semantic_score=sem_score)
        allowed = clf.intent == "SAFE" or clf.confidence < 0.85
        return TierResult(allowed, prompt, 0.5 if not allowed else 0.0, {
            "intent": clf.intent, 
            "confidence": clf.confidence,
            "rationale": clf.rationale
        })

class PIIDetectorTier(SecurityTier):
    @property
    def name(self): return "PIIDetector"
    def execute(self, prompt, context):
        pii = detect_and_redact(prompt)
        return TierResult(True, pii.redacted_text, pii.score, {
            "detected": pii.detected,
            "entities": pii.entities
        })

class PolicyEngineTier(SecurityTier):
    @property
    def name(self): return "PolicyEngine"
    def execute(self, prompt, context):
        dept = context.get("department", "unknown")
        role = context.get("role", "user")
        policy = evaluate_policy(department=dept, role=role, prompt=prompt)
        return TierResult(policy.allowed, prompt, policy.score, {
            "allowed": policy.allowed,
            "reason": policy.reason
        })

class SemanticEngineTier(SecurityTier):
    @property
    def name(self): return "SemanticEngine"
    def execute(self, prompt, context):
        sem = semantic_scan(prompt)
        return TierResult(True, prompt, min(0.6, sem.score), {
            "score": sem.score,
            "matched": sem.matched_example
        })

def create_default_orchestrator() -> SecurityOrchestrator:
    """Factory to create a standard enterprise security pipeline."""
    return (
        SecurityOrchestrator()
        .add_tier(NormalizationTier())
        .add_tier(RuleEngineTier())
        .add_tier(SemanticEngineTier())
        .add_tier(LLMClassifierTier())
        .add_tier(PolicyEngineTier())
        .add_tier(PIIDetectorTier())
    )
