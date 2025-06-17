import math
import string
from typing import Dict, Any, List

def calculate_entropy(password: str) -> float:
    """
    Calculates the Shannon entropy of a password in bits.
    
    Formula: Entropy = L * log2(R)
    where L = length of password
    R = size of character pool used
    """
    if not password:
        return 0.0

    length = len(password)
    pool_size = 0

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += 33  # Standard printable symbols and space

    if pool_size == 0:
        return 0.0

    return length * math.log2(pool_size)

def analyze_length(password: str) -> Dict[str, Any]:
    """
    Analyzes the length of a password and returns severity and assessment details.
    
    Security reasoning:
    Length is the single most critical factor in password strength. A longer password
    exponentially increases the search space for brute force attacks.
    """
    length = len(password)
    
    if length < 8:
        return {
            "length": length,
            "severity": "CRITICAL",
            "status": "Too Short",
            "message": "Password is under 8 characters. Modern hardware can brute-force this in minutes/seconds.",
            "suggestion": "Increase password length to at least 12 (ideally 16+) characters."
        }
    elif length < 12:
        return {
            "length": length,
            "severity": "WARNING",
            "status": "Weak Length",
            "message": "Password length is between 8 and 11 characters. Vulnerable to advanced offline brute-forcing.",
            "suggestion": "Add 4 or more characters to reach the recommended 12+ character threshold."
        }
    elif length < 16:
        return {
            "length": length,
            "severity": "OK",
            "status": "Good Length",
            "message": "Password length is between 12 and 15 characters. Generally secure if complex.",
            "suggestion": "Consider making it even longer (16+ characters) to create a passphrase."
        }
    else:
        return {
            "length": length,
            "severity": "SAFE",
            "status": "Excellent Length",
            "message": "Password is 16 or more characters. Highly resistant to brute-force attacks.",
            "suggestion": ""
        }

def get_base_strength_score(entropy: float, length: int) -> str:
    """
    Returns the strength score based on entropy and length.
    
    Scores: Very Weak / Weak / Moderate / Strong / Very Strong
    """
    # Base scoring by entropy (in bits)
    if entropy < 36:
        score = "Very Weak"
    elif entropy < 60:
        score = "Weak"
    elif entropy < 80:
        score = "Moderate"
    elif entropy < 120:
        score = "Strong"
    else:
        score = "Very Strong"

    # Length constraints / downgrades for safety
    if length < 8:
        score = "Very Weak"
    elif length < 12 and score in ["Strong", "Very Strong"]:
        score = "Moderate"

    return score
