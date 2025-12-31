import dns.resolver

def resolve_record(domain, record_type):
    """
    Helper to resolve specific DNS records with built-in error handling.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []

def get_mx_ip(mx_records):
    """
    Extra credit: Resolves the IP addresses of the Mail Servers.
    """
    ips = []
    for record in mx_records:
        # mx_records usually look like "10 mail.google.com."
        host = record.split(' ')[-1].strip('.')
        try:
            import socket
            ips.append(socket.gethostbyname(host))
        except:
            continue
    return list(set(ips))