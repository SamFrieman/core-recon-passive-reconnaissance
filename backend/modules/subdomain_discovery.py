import requests

def get_subdomains(domain):
    """
    Queries crt.sh for subdomain enumeration via Certificate Transparency logs.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                # crt.sh often returns multiple names per entry separated by newlines
                names = entry['name_value'].lower().split('\n')
                for name in names:
                    clean_name = name.replace('*.', '').strip()
                    if clean_name.endswith(domain):
                        subdomains.add(clean_name)
        return sorted(list(subdomains))
    except Exception as e:
        return {"error": f"Subdomain lookup failed: {str(e)}"}