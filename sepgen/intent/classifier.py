from typing import List
from sepgen.models.access import Access
from sepgen.models.intent import Intent, IntentType
from sepgen.intent.rules import DEFAULT_RULES


class IntentClassifier:
    """Classify system accesses into security intents"""

    def __init__(self, rules=None):
        self.rules = rules or DEFAULT_RULES

    def classify(self, accesses: List[Access]) -> List[Intent]:
        """Classify a list of accesses into intents"""
        intents = []

        for access in accesses:
            matched = False

            for rule in self.rules:
                if rule.matches(access):
                    intent = Intent(
                        intent_type=rule.get_intent_type(),
                        accesses=[access],
                        confidence=rule.get_confidence()
                    )
                    intents.append(intent)
                    matched = True
                    break

            if not matched:
                intent = Intent(
                    intent_type=IntentType.UNKNOWN,
                    accesses=[access],
                    confidence=0.5
                )
                intents.append(intent)

        return intents
