import csv
import json
import hashlib
from typing import List, Dict, Any, Tuple
from passguard.entropy import calculate_entropy, analyze_length, get_base_strength_score
from passguard.patterns import analyze_patterns
from passguard.breach import lookup_breach
from passguard.common import is_common_password

def mask_password(password: str) -> str:
    """
    Masks the password for safe logging/reporting.
    e.g., 'password123' -> 'p*********3 (length: 11)'
    """
    length = len(password)
    if length <= 2:
        return "*" * length
    elif length <= 5:
        return password[0] + "*" * (length - 1)
    else:
        return f"{password[0]}{'*' * (length - 2)}{password[-1]} (len: {length})"

def generate_suggestions(password: str, entropy_val: float, pattern_data: Dict[str, Any], is_common: bool, breach_count: int) -> List[str]:
    """
    Generates 2-3 actionable security suggestions to improve password strength.
    """
    suggestions = []
    length = len(password)

    # 1. Critical safety overrides
    if breach_count > 0:
        suggestions.append("Stop using this password immediately; it is compromised in data breaches.")
    if is_common:
        suggestions.append("Choose a unique password; this is in the top 10,000 most commonly used passwords.")

    # 2. Length suggestion
    if length < 12:
        suggestions.append(f"Increase the length to at least 12 characters (currently {length}). passphrases of 16+ chars are highly recommended.")

    # 3. Complexity/character pool suggestions
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if not has_upper:
        suggestions.append("Include uppercase characters (A-Z).")
    if not has_lower:
        suggestions.append("Include lowercase characters (a-z).")
    if not has_digit:
        suggestions.append("Include numerical digits (0-9).")
    if not has_special:
        suggestions.append("Include special symbols (e.g. !, @, #, $, %).")

    # 4. Pattern-specific suggestions
    if pattern_data.get("repeated_characters"):
        suggestions.append("Avoid repeating the same character sequentially (e.g. 'aaa').")
    if pattern_data.get("sequential_characters"):
        suggestions.append("Avoid keyboard or alphabetical sequences (e.g. '123', 'abc').")
    if pattern_data.get("keyboard_patterns"):
        suggestions.append("Avoid adjacent keyboard patterns (e.g. 'qwerty').")

    # Default fallback suggestions
    if len(suggestions) < 2:
        suggestions.append("Use a reputable password manager to generate and store long, unique credentials.")
    if len(suggestions) < 3:
        suggestions.append("Combine 4-5 random, unrelated words to create a strong, memorable passphrase.")

    # Limit to top 3 suggestions
    return suggestions[:3]

def analyze_password(password: str, check_breach: bool = True) -> Dict[str, Any]:
    """
    Runs a full suite of analyses on a single password.
    
    Important: The input password is only held in memory temporarily.
    """
    if not password:
        return {
            "masked_password": "",
            "length": 0,
            "entropy": 0.0,
            "score": "Very Weak",
            "is_common": False,
            "breach_count": 0,
            "weaknesses": ["Empty password"],
            "suggestions": ["Enter a non-empty password."],
            "breach_error": None,
            "common_error": None
        }

    # 1. Entropy and length
    entropy_val = calculate_entropy(password)
    length_analysis = analyze_length(password)
    
    # 2. Pattern detection
    pattern_analysis = analyze_patterns(password)
    
    # 3. Common password check
    is_common, common_err = is_common_password(password)
    
    # 4. Breach lookup (Have I Been Pwned API)
    breach_count = 0
    breach_err = None
    if check_breach:
        breach_count, breach_err = lookup_breach(password)

    # 5. Weaknesses assessment
    weaknesses = []
    if length_analysis["severity"] == "CRITICAL":
        weaknesses.append("Critically short (less than 8 characters)")
    elif length_analysis["severity"] == "WARNING":
        weaknesses.append("Too short (less than 12 characters)")
        
    if is_common:
        weaknesses.append("Found in list of top 10,000 common passwords")
        
    if breach_count > 0:
        weaknesses.append(f"Exposed in public data breaches ({breach_count:,} times)")
        
    if pattern_analysis["repeated_characters"]:
        weaknesses.append(f"Contains repeated character sequences: {', '.join(pattern_analysis['repeated_characters'])}")
        
    if pattern_analysis["sequential_characters"]:
        weaknesses.append(f"Contains alphabetical/numeric runs: {', '.join(pattern_analysis['sequential_characters'])}")
        
    if pattern_analysis["keyboard_patterns"]:
        weaknesses.append(f"Contains keyboard patterns: {', '.join(pattern_analysis['keyboard_patterns'])}")

    # 6. Scoring overrides
    base_score = get_base_strength_score(entropy_val, len(password))
    
    # Apply severe downgrades
    if is_common or breach_count > 100 or len(password) < 8:
        final_score = "Very Weak"
    elif breach_count > 0 or pattern_analysis["findings_count"] >= 3:
        # If breached or lots of patterns, downgrade to Weak
        final_score = "Weak"
    elif pattern_analysis["has_patterns"] and base_score in ["Strong", "Very Strong"]:
        final_score = "Moderate"
    else:
        final_score = base_score

    suggestions = generate_suggestions(password, entropy_val, pattern_analysis, is_common, breach_count)

    # Generate a SHA-256 fingerprint for identification in reports without storing password
    sha256_fingerprint = hashlib.sha256(password.encode("utf-8")).hexdigest()[:16]

    return {
        "fingerprint": sha256_fingerprint,
        "masked_password": mask_password(password),
        "length": len(password),
        "entropy": round(entropy_val, 2),
        "score": final_score,
        "is_common": is_common,
        "breach_count": breach_count,
        "weaknesses": weaknesses,
        "suggestions": suggestions,
        "breach_error": breach_err,
        "common_error": common_err
    }

def export_to_csv(filepath: str, results: List[Dict[str, Any]]) -> None:
    """
    Exports audit results to a CSV file.
    Note: Password strings are never stored or exported; only masked values and stats.
    """
    fieldnames = ["fingerprint", "masked_password", "length", "entropy", "score", "is_common", "breach_count", "weaknesses", "suggestions"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "fingerprint": r["fingerprint"],
                "masked_password": r["masked_password"],
                "length": r["length"],
                "entropy": r["entropy"],
                "score": r["score"],
                "is_common": r["is_common"],
                "breach_count": r["breach_count"],
                "weaknesses": "; ".join(r["weaknesses"]),
                "suggestions": "; ".join(r["suggestions"])
            })

def export_to_json(filepath: str, results: List[Dict[str, Any]]) -> None:
    """
    Exports audit results to a JSON file.
    Note: Password strings are never stored or exported; only masked values and stats.
    """
    cleaned_results = []
    for r in results:
        cleaned_results.append({
            "fingerprint": r["fingerprint"],
            "masked_password": r["masked_password"],
            "length": r["length"],
            "entropy": r["entropy"],
            "score": r["score"],
            "is_common": r["is_common"],
            "breach_count": r["breach_count"],
            "weaknesses": r["weaknesses"],
            "suggestions": r["suggestions"]
        })
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(cleaned_results, f, indent=4)
