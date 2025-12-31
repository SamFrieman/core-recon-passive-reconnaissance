import requests

def get_osint_data(domain):
    """
    PASSIVE OSINT: Queries the Wayback Machine for historical URLs.
    This helps identify hidden directories or old files.
    """
    results = {"wayback_urls": []}
    try:
        # Querying the Wayback Machine CDX API
        url = f"http://web.archive.org/cdx/search/xd?url={domain}/*&output=json&limit=10"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:
                # Skip the header row and extract unique URLs
                results["wayback_urls"] = list(set([item[2] for item in data[1:]]))
    except Exception as e:
        results["error"] = f"Wayback lookup failed: {str(e)}"
    
    return results