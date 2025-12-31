import requests
import socket

def get_infrastructure_info(domain):
    """
    PASSIVE RECON: Identifies IP, Geolocation, and ASN.
    """
    results = {}
    try:
        # 1. Get the IP address via standard DNS resolution
        ip_address = socket.gethostbyname(domain)
        results['ip'] = ip_address

        # 2. Query a public GeoIP API
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,as,org")
        
        if response.status_code == 200:
            geo_data = response.json()
            if geo_data.get('status') == 'success':
                results['location'] = f"{geo_data.get('city')}, {geo_data.get('country')}"
                results['isp'] = geo_data.get('isp')
                results['asn'] = geo_data.get('as')
                results['organization'] = geo_data.get('org')
        
    except Exception as e:
        results['error'] = f"Infrastructure lookup failed: {str(e)}"
        
    return results