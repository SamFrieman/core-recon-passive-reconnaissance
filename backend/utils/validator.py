import re

def validate_domain(domain: str) -> bool:
    """
    Validates that the input is a properly formatted domain name.
    """
    # Regex for a standard domain name
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    
    if not domain:
        return False
    
    # Remove protocol if user accidentally included it
    clean_domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
    
    return re.match(pattern, clean_domain, re.IGNORECASE) is not None

def clean_domain_input(domain: str) -> str:
    """Removes protocols and trailing slashes."""
    return domain.replace("http://", "").replace("https://", "").split('/')[0].strip().lower()