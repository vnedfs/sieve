"""
Quarantine stage: Untrusted processing.

Threat mitigated: Direct and indirect prompt injection
Invariant: Untrusted data never directly influences decisions

Key constraint: This stage has NO tool access, NO secrets, NO decision-making authority.

Mathematical Property: CSO must contain ONLY structured fields, NO free text that could be interpreted as instructions.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import re

from sieve.models import (
    ContentSummaryObject,
    TaintLevel,
    RiskSignals,
)
from sieve.normalize import normalize_text


class StructuredExtraction:
    """
    Structured extraction of intent and entities from untrusted data.
    
    This class extracts ONLY structured fields:
    - Intent (categorical, not free text)
    - Entities (named entities, not raw text)
    - Topics (keywords, not sentences)
    - Metadata (counts, flags, not content)
    
    NO free text that could be interpreted as instructions.
    """
    
    @staticmethod
    def extract_intent(text: str) -> str:
        """
        Extract intent as a categorical value.
        
        Returns one of: "question", "command", "statement", "unknown"
        Not free text that could contain instructions.
        """
        text_lower = text.lower().strip()
        
        # Question patterns
        if any(text_lower.startswith(q) for q in ["what", "who", "where", "when", "why", "how"]):
            return "question"
        if "?" in text:
            return "question"
        
        # Command patterns
        if any(text_lower.startswith(cmd) for cmd in ["please", "can you", "do", "make", "create", "delete"]):
            return "command"
        if any(cmd in text_lower for cmd in ["execute", "run", "call", "invoke"]):
            return "command"
        
        # Statement
        if len(text.split()) > 3:
            return "statement"
        
        return "unknown"
    
    @staticmethod
    def extract_entities(text: str) -> List[Dict[str, str]]:
        """
        Extract named entities (simplified).
        
        In production, this would use NER (Named Entity Recognition).
        Returns structured entities, not raw text.
        """
        entities = []
        
        # Simple pattern matching (in production, use proper NER)
        # Email patterns
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        for email in emails:
            entities.append({"type": "email", "value": email})
        
        # URL patterns
        urls = re.findall(r'https?://[^\s]+', text)
        for url in urls:
            entities.append({"type": "url", "value": url})
        
        # Numbers (potential IDs, amounts, etc.)
        numbers = re.findall(r'\b\d+\b', text)
        if numbers:
            entities.append({"type": "number", "value": numbers[0]})  # First number
        
        return entities
    
    @staticmethod
    def extract_topics(text: str, max_topics: int = 5) -> List[str]:
        """
        Extract topics as keywords.
        
        Returns list of keywords, not sentences or instructions.
        """
        # Simple keyword extraction (in production, use proper topic modeling)
        words = re.findall(r'\b[a-z]{4,}\b', text.lower())
        
        # Filter common stop words
        stop_words = {"this", "that", "with", "from", "have", "been", "will", "would", "should"}
        keywords = [w for w in words if w not in stop_words]
        
        # Count frequency and return top N
        from collections import Counter
        word_counts = Counter(keywords)
        top_words = [word for word, _ in word_counts.most_common(max_topics)]
        
        return top_words


class QuarantineProcessor:
    """
    Processes untrusted data in isolation.
    
    This stage:
    1. Normalizes input (strips obfuscation)
    2. Extracts structured representation (CSO) - NO FREE TEXT
    3. Detects suspicious patterns
    4. Returns CSO + risk signals
    
    Mathematical Property:
    CSO.summary must be a structured representation, not raw text.
    In this implementation, summary is a JSON-like string of structured fields.
    
    It does NOT:
    - Access tools
    - Access secrets
    - Make decisions
    - Process raw untrusted text in privileged contexts
    """
    
    def __init__(self):
        """Initialize quarantine processor."""
        self.extractor = StructuredExtraction()
    
    def process(self, 
                raw_data: str, 
                source: Optional[str] = None) -> ContentSummaryObject:
        """
        Process untrusted data and extract structured representation.
        
        Args:
            raw_data: Raw untrusted input
            source: Optional source identifier (e.g., "user_input", "rag_doc_123")
            
        Returns:
            ContentSummaryObject with structured, sanitized content
            CRITICAL: summary field contains structured data, NOT free text
        """
        # Step 1: Normalize input
        normalized, risk_signals = normalize_text(raw_data)
        
        # Step 2: Extract structured representation
        # This is the key: we extract ONLY structured fields, NO free text
        structured_data = self._extract_structured(normalized)
        
        # Step 3: Create summary as structured JSON string (not free text)
        # This ensures the privileged layer receives structured data, not instructions
        import json
        summary = json.dumps(structured_data, sort_keys=True)
        
        # Step 4: Extract metadata
        metadata = self._extract_metadata(normalized)
        
        # Step 5: Create CSO
        cso = ContentSummaryObject(
            summary=summary,  # Structured JSON, not free text
            metadata=metadata,
            taint=TaintLevel.UNTRUSTED,  # Always UNTRUSTED for CSO
            risk_signals=risk_signals,
            source=source,
            timestamp=datetime.utcnow(),
        )
        
        return cso
    
    def _extract_structured(self, normalized_text: str) -> Dict[str, Any]:
        """
        Extract structured representation from normalized text.
        
        Returns ONLY structured fields:
        - intent: categorical value
        - entities: list of structured entities
        - topics: list of keywords
        - flags: boolean flags
        
        NO free text that could be interpreted as instructions.
        """
        structured = {
            "intent": self.extractor.extract_intent(normalized_text),
            "entities": self.extractor.extract_entities(normalized_text),
            "topics": self.extractor.extract_topics(normalized_text),
            "flags": {
                "has_question": "?" in normalized_text,
                "has_command_words": any(cmd in normalized_text.lower() for cmd in ["please", "can you", "do"]),
                "length_category": self._categorize_length(len(normalized_text)),
            },
        }
        
        return structured
    
    def _categorize_length(self, length: int) -> str:
        """Categorize text length (structured, not raw number)."""
        if length < 50:
            return "short"
        elif length < 200:
            return "medium"
        else:
            return "long"
    
    def _extract_metadata(self, normalized_text: str) -> dict:
        """
        Extract structured metadata from normalized text.
        
        Returns metadata that can be safely used for decision-making
        without exposing raw untrusted content.
        """
        metadata = {
            "length": len(normalized_text),
            "word_count": len(normalized_text.split()),
            "has_questions": "?" in normalized_text,
            "has_commands": any(cmd in normalized_text.lower() for cmd in ["please", "can you", "do", "execute"]),
            "sentence_count": len(re.split(r'[.!?]+', normalized_text)),
        }
        
        # Extract topics/keywords (structured, not raw text)
        topics = self.extractor.extract_topics(normalized_text, max_topics=10)
        metadata["keywords"] = topics
        
        return metadata
    
    def _looks_like_instruction(self, text: str) -> bool:
        """
        Check if text looks like an instruction.
        
        This is a heuristic check. In production, this might be more sophisticated.
        """
        text_lower = text.lower()
        
        # Check for imperative patterns
        imperative_patterns = [
            "ignore",
            "forget",
            "disregard",
            "you are",
            "act as",
            "pretend",
            "system:",
            "instruction:",
            "new instruction",
            "override",
            "bypass",
        ]
        
        for pattern in imperative_patterns:
            if pattern in text_lower:
                return True
        
        # Check for command-like structure
        if text_lower.startswith(("do ", "make ", "create ", "delete ", "execute ", "run ")):
            return True
        
        return False


# Global instance
_quarantine_processor = None


def get_quarantine_processor() -> QuarantineProcessor:
    """Get singleton quarantine processor."""
    global _quarantine_processor
    if _quarantine_processor is None:
        _quarantine_processor = QuarantineProcessor()
    return _quarantine_processor


def quarantine(raw_data: str, source: Optional[str] = None) -> ContentSummaryObject:
    """
    Convenience function to quarantine untrusted data.
    
    Args:
        raw_data: Raw untrusted input
        source: Optional source identifier
        
    Returns:
        ContentSummaryObject with structured data (not free text)
    """
    processor = get_quarantine_processor()
    return processor.process(raw_data, source)
