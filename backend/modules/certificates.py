import ssl
import socket
from datetime import datetime

def get_certificate_details(domain):
    """
    PASSIVE CERT INTEL: Extracts technical details of the SSL/TLS certificate.
    """
    results = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extracting key dates
                results['issuer'] = dict(x[0] for x in cert['issuer'])['organizationName']
                results['subject'] = dict(x[0] for x in cert['subject'])['commonName']
                results['version'] = cert.get('version')
                
                # Convert dates
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                results['days_until_expiry'] = (expires - datetime.utcnow()).days
                results['is_expired'] = datetime.utcnow() > expires

    except Exception as e:
        results['error'] = f"Certificate lookup failed: {str(e)}"
    
    return results