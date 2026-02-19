"""
Input normalization layer.

Threat mitigated: Obfuscation attacks (zero-width chars, unicode tricks)
Invariant: All inputs are normalized to canonical form before processing
"""

import re
import unicodedata
from typing import List, Tuple

from sieve.models import RiskSignals, RiskLevel


# Zero-width characters that can be used for obfuscation
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\ufeff',  # Zero-width no-break space
    '\u180e',  # Mongolian vowel separator
]

# Suspicious instruction-like patterns
INSTRUCTION_PATTERNS = [
    r'ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions?',
    r'forget\s+(all\s+)?(previous|prior|earlier)\s+instructions?',
    r'disregard\s+(all\s+)?(previous|prior|earlier)\s+instructions?',
    r'you\s+are\s+now\s+',
    r'act\s+as\s+if\s+you\s+are\s+',
    r'pretend\s+to\s+be\s+',
    r'system\s*:\s*',
    r'instruction\s*:\s*',
    r'new\s+instructions?\s*:',
    r'override\s+',
    r'bypass\s+',
    r'jailbreak',
    r'developer\s+mode',
    r'god\s+mode',
]

# Suspicious keywords that might indicate injection attempts
SUSPICIOUS_KEYWORDS = [
    'system prompt',
    'api key',
    'secret',
    'password',
    'token',
    'credential',
    'exfiltrate',
    'extract',
    'reveal',
    'show me',
    'tell me',
    'output',
    'print',
    'execute',
    'run',
    'delete',
    'remove',
    'modify',
    'change',
]


def normalize_text(text: str) -> Tuple[str, RiskSignals]:
    """
    Normalize input text and detect obfuscation.
    
    Args:
        text: Raw input text
        
    Returns:
        Tuple of (normalized_text, risk_signals)
    """
    risk_signals = RiskSignals()
    normalized = text
    
    # Detect zero-width characters
    zero_width_found = []
    for char in ZERO_WIDTH_CHARS:
        if char in normalized:
            zero_width_found.append(char)
            risk_signals.has_zero_width_chars = True
    
    # Remove zero-width characters
    for char in ZERO_WIDTH_CHARS:
        normalized = normalized.replace(char, '')
    
    # Unicode normalization (NFKC: compatibility decomposition + composition)
    # This normalizes similar-looking characters to canonical form
    normalized = unicodedata.normalize('NFKC', normalized)
    
    # Detect instruction-like patterns
    instruction_matches = []
    for pattern in INSTRUCTION_PATTERNS:
        matches = re.findall(pattern, normalized, re.IGNORECASE)
        if matches:
            instruction_matches.extend(matches)
            risk_signals.has_instruction_patterns = True
    
    # Detect suspicious keywords
    found_keywords = []
    text_lower = normalized.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            found_keywords.append(keyword)
    
    risk_signals.suspicious_keywords = found_keywords
    
    # Check for other obfuscation techniques
    # Mixed case obfuscation (e.g., "IgNoRe PrEvIoUs")
    if re.search(r'[A-Z][a-z]+[A-Z]', normalized):
        risk_signals.has_obfuscation = True
    
    # Excessive whitespace (potential hiding)
    if re.search(r'\s{5,}', normalized):
        risk_signals.has_obfuscation = True
    
    # Calculate risk score
    risk_score = 0.0
    
    if risk_signals.has_instruction_patterns:
        risk_score += 0.5
    if risk_signals.has_zero_width_chars:
        risk_score += 0.3
    if risk_signals.has_obfuscation:
        risk_score += 0.2
    if len(found_keywords) > 0:
        risk_score += min(0.2, len(found_keywords) * 0.05)
    
    risk_score = min(1.0, risk_score)
    risk_signals.risk_score = risk_score
    
    # Determine risk level
    if risk_score >= 0.7:
        risk_signals.risk_level = RiskLevel.CRITICAL
    elif risk_score >= 0.5:
        risk_signals.risk_level = RiskLevel.HIGH
    elif risk_score >= 0.3:
        risk_signals.risk_level = RiskLevel.MEDIUM
    else:
        risk_signals.risk_level = RiskLevel.LOW
    
    return normalized, risk_signals


def strip_control_chars(text: str) -> str:
    """Remove control characters except newlines and tabs."""
    return ''.join(char for char in text if unicodedata.category(char)[0] != 'C' or char in '\n\t')


def detect_hidden_text(text: str) -> bool:
    """
    Detect potentially hidden text (e.g., same color as background).
    
    Note: This is a simplified check. Full detection would require
    rendering context which we don't have here.
    """
    # Check for excessive whitespace that might hide text
    if re.search(r'\s{10,}', text):
        return True
    
    # Check for zero-width characters (already handled, but double-check)
    for char in ZERO_WIDTH_CHARS:
        if char in text:
            return True
    
    return False

