import hashlib
import requests
from typing import Tuple, Optional

def lookup_breach(password: str) -> Tuple[int, Optional[str]]:
    """
    Looks up a password in the Have I Been Pwned database using the k-Anonymity model.
    
    Security reasoning:
    By hashing the password and sending only the first 5 characters of the SHA-1 hash,
    the remote API server never learns the password or even its full hash. This preserves
    the user's privacy while enabling checking against billions of leaked credentials.
    
    Returns:
        A tuple of (breach_count, error_message). 
        If the password is not found, breach_count will be 0.
        If a network or API error occurs, error_message will contain details.
    """
    if not password:
        return 0, None

    try:
        # Compute SHA-1 hash locally
        sha1_hex = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hex[:5]
        suffix = sha1_hex[5:]

        # Query the API with the 5-character prefix
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {
            "User-Agent": "PassGuard-CLI-Security-Tool"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return 0, f"API error (Status Code: {response.status_code})"

        # Search for our suffix in the returned hashes
        for line in response.text.splitlines():
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                returned_suffix, count_str = parts
                if returned_suffix.upper() == suffix:
                    try:
                        return int(count_str), None
                    except ValueError:
                        return 0, "Invalid count returned by API"

        # Not found in the breach database
        return 0, None

    except requests.exceptions.RequestException as e:
        return 0, f"Connection failed: {str(e)}"
    except Exception as e:
        return 0, f"Unexpected error during breach check: {str(e)}"
