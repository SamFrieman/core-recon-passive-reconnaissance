import whois
import dns.resolver

def get_domain_info(domain): # <--- Check this name carefully!
    results = {}
    try:
        # WHOIS Lookup
        w = whois.whois(domain)
        results['registrar'] = w.registrar
        results['creation_date'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        
        # DNS Record Lookup
        results['dns'] = {}
        for record_type in ['A', 'MX', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns'][record_type] = [str(rdata) for rdata in answers]
            except:
                results['dns'][record_type] = []
                
    except Exception as e:
        results['error'] = str(e)
    return results