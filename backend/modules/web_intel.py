import requests

def get_web_intel(domain):
    """
    PASSIVE WEB INTEL: Analyzes public headers and security flags.
    This is passive as we are only reading the 'front-door' headers.
    """
    results = {}
    try:
        # We use a HEAD request or a limited GET to see only headers
        url = f"http://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        results['server'] = response.headers.get('Server', 'Hidden')
        results['content_type'] = response.headers.get('Content-Type')
        results['security_headers'] = {
            "X-Frame-Options": response.headers.get('X-Frame-Options'),
            "Content-Security-Policy": "Present" if 'Content-Security-Policy' in response.headers else "Missing",
            "Strict-Transport-Security": "Present" if 'Strict-Transport-Security' in response.headers else "Missing"
        }
    except Exception as e:
        results['error'] = f"Web intel failed: {str(e)}"
    
    return results