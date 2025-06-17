import os
import requests
from typing import Set, Tuple, Optional

URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
CACHE_DIR = os.path.expanduser("~/.passguard")
CACHE_FILE = os.path.join(CACHE_DIR, "10k-most-common.txt")

_cached_passwords: Optional[Set[str]] = None

def download_common_passwords() -> Tuple[bool, Optional[str]]:
    """
    Downloads the top 10,000 common passwords from SecLists and caches it locally.
    
    Returns:
        (success, error_message)
    """
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        
        headers = {
            "User-Agent": "PassGuard-CLI-Tool"
        }
        response = requests.get(URL, headers=headers, timeout=15)
        
        if response.status_code != 200:
            return False, f"Failed to download list. HTTP Status: {response.status_code}"
            
        # Write to local cache
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)
            
        return True, None
    except requests.exceptions.RequestException as e:
        return False, f"Network connection failed: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error during download: {str(e)}"

def load_common_passwords(force_download: bool = False) -> Tuple[Set[str], Optional[str]]:
    """
    Loads the cached top 10k common passwords. If the file is not cached,
    it downloads it first.
    
    Returns:
        A tuple of (set_of_passwords, error_message).
    """
    global _cached_passwords
    if _cached_passwords is not None and not force_download:
        return _cached_passwords, None

    # Check if we need to download it
    if not os.path.exists(CACHE_FILE) or force_download:
        success, err = download_common_passwords()
        if not success:
            return set(), f"Could not load 10k common password list. {err or ''}"

    try:
        passwords = set()
        with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned:
                    passwords.add(cleaned)
        _cached_passwords = passwords
        return passwords, None
    except Exception as e:
        return set(), f"Error reading cached password list: {str(e)}"

def is_common_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a password exists in the cached 10k common passwords list.
    
    Security reasoning:
    Attackers always test the most common passwords first. If a password is in the
    top 10k, it will be broken instantly in any credential stuffing or brute force attack,
    regardless of its theoretical entropy or length.
    
    Returns:
        (is_common, error_message)
    """
    passwords_set, err = load_common_passwords()
    if err:
        return False, err
    # Compare case-sensitively or case-insensitively?
    # Common password lists are typically lowercase, but they could be exact.
    # To be safe, check both exact match and lowercase match.
    return (password in passwords_set) or (password.lower() in passwords_set), None
