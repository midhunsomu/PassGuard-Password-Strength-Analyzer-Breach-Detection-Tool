from typing import List, Dict, Any

KEYBOARD_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

def find_repeated_patterns(password: str) -> List[str]:
    """
    Finds sequences of repeated identical characters of length >= 3.
    e.g., 'aaa', '1111'
    """
    if len(password) < 3:
        return []

    repeats = []
    current_char = password[0]
    current_len = 1
    
    for i in range(1, len(password)):
        if password[i] == current_char:
            current_len += 1
        else:
            if current_len >= 3:
                repeats.append(current_char * current_len)
            current_char = password[i]
            current_len = 1
            
    if current_len >= 3:
        repeats.append(current_char * current_len)
        
    return repeats

def find_sequential_patterns(password: str) -> List[str]:
    """
    Finds alphabetical or numeric sequences of length >= 3.
    e.g., 'abc', '789', 'zyx', '321' (case-insensitive)
    """
    if len(password) < 3:
        return []

    sequences = []
    n = len(password)
    i = 0
    
    while i < n - 2:
        char_i = password[i]
        is_digit = char_i.isdigit()
        is_alpha = char_i.isalpha()
        
        if not (is_digit or is_alpha):
            i += 1
            continue
            
        next_char = password[i+1]
        if is_digit and next_char.isdigit():
            diff = ord(next_char) - ord(char_i)
        elif is_alpha and next_char.isalpha():
            diff = ord(next_char.lower()) - ord(char_i.lower())
        else:
            i += 1
            continue
            
        if diff not in (1, -1):
            i += 1
            continue
            
        run_len = 2
        j = i + 2
        while j < n:
            curr = password[j]
            prev = password[j-1]
            if is_digit and curr.isdigit():
                curr_diff = ord(curr) - ord(prev)
            elif is_alpha and curr.isalpha():
                curr_diff = ord(curr.lower()) - ord(prev.lower())
            else:
                break
                
            if curr_diff == diff:
                run_len += 1
                j += 1
            else:
                break
                
        if run_len >= 3:
            sequences.append(password[i:i+run_len])
            i += run_len - 1
        else:
            i += 1
            
    return sequences

def find_keyboard_patterns(password: str) -> List[str]:
    """
    Finds keyboard patterns of length >= 3 (adjacent keys on standard QWERTY rows).
    e.g., 'qwe', 'asdf', 'rewq' (case-insensitive)
    """
    if len(password) < 3:
        return []

    pwd_lower = password.lower()
    patterns = []
    n = len(pwd_lower)
    i = 0
    
    while i < n - 2:
        max_run = 0
        for row in KEYBOARD_ROWS:
            if pwd_lower[i] not in row:
                continue
                
            idx_i = row.index(pwd_lower[i])
            if pwd_lower[i+1] not in row:
                continue
                
            idx_next = row.index(pwd_lower[i+1])
            diff = idx_next - idx_i
            if diff not in (1, -1):
                continue
                
            run_len = 2
            j = i + 2
            while j < n:
                if pwd_lower[j] not in row:
                    break
                idx_curr = row.index(pwd_lower[j])
                idx_prev = row.index(pwd_lower[j-1])
                if idx_curr - idx_prev == diff:
                    run_len += 1
                    j += 1
                else:
                    break
            if run_len >= 3:
                max_run = max(max_run, run_len)
                
        if max_run >= 3:
            patterns.append(password[i:i+max_run])
            i += max_run - 1
        else:
            i += 1
            
    return patterns

def analyze_patterns(password: str) -> Dict[str, Any]:
    """
    Analyzes the password for common keyboard, sequential, and repeated patterns.
    
    Security reasoning:
    Attackers use dictionaries with rule-based modifications (e.g. keyboard runs,
    common increments) because humans are highly predictable in their password patterns.
    Even if a password is long, patterns drastically reduce the actual security.
    """
    repeats = find_repeated_patterns(password)
    sequences = find_sequential_patterns(password)
    keyboard = find_keyboard_patterns(password)
    
    # De-duplicate patterns that might match multiple rules if they are overlapping
    # but for report representation, showing them separately is fine.
    
    total_findings = len(repeats) + len(sequences) + len(keyboard)
    
    return {
        "repeated_characters": repeats,
        "sequential_characters": sequences,
        "keyboard_patterns": keyboard,
        "has_patterns": total_findings > 0,
        "findings_count": total_findings
    }
