import socket
import ssl
import dns.resolver
import whois
import requests
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")

from Wappalyzer import Wappalyzer, WebPage
from fastapi import FastAPI, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fpdf import FPDF
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import re
import ipaddress
from urllib.parse import urlparse

app = FastAPI(title="CoreRecon Intelligence API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== DATABASE ====================
def init_db():
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (domain TEXT PRIMARY KEY, 
                  data TEXT, 
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  scan_count INTEGER DEFAULT 1)''')
    conn.commit()
    conn.close()

init_db()

# ==================== INPUT VALIDATION & SANITIZATION ====================

def sanitize_input(user_input: str) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks
    Remove dangerous characters while preserving valid domain/IP characters
    """
    if not user_input:
        raise ValueError("Input cannot be empty")
    
    # Remove any HTML/script tags (XSS prevention)
    user_input = re.sub(r'<[^>]*>', '', user_input)
    
    # Remove SQL injection patterns
    sql_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|;|\/\*|\*\/)',
        r'(\bOR\b.*=.*)',
        r'(\bAND\b.*=.*)',
        r"('|\"|\`)",
    ]
    for pattern in sql_patterns:
        user_input = re.sub(pattern, '', user_input, flags=re.IGNORECASE)
    
    # Remove special characters except valid domain/IP/hash characters
    user_input = re.sub(r'[^\w\.\-\:\/]', '', user_input)
    
    # Limit length to prevent buffer overflow
    if len(user_input) > 255:
        raise ValueError("Input too long (max 255 characters)")
    
    return user_input.strip()



# ==================== HELPER FUNCTIONS ====================

def normalize_domain(domain: str) -> str:
    """Remove http/https and trailing slashes - DEPRECATED, use validate_and_normalize_input"""
    return domain.replace('http://', '').replace('https://', '').replace('www.', '').strip('/')

def get_scan_history(domain: str) -> Dict[str, Any]:
    """Get historical scan data for correlation"""
    try:
        conn = sqlite3.connect('recon_history.db')
        c = conn.cursor()
        c.execute("SELECT scan_count, timestamp FROM scans WHERE domain=?", (domain,))
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                "previous_scans": row[0],
                "last_scan": row[1],
                "status": "REPEAT_TARGET" if row[0] > 1 else "FIRST_SCAN"
            }
        return {"previous_scans": 0, "status": "NEW_TARGET"}
    except:
        return {"error": "History unavailable"}

# ==================== RECONNAISSANCE MODULES ====================

def get_infrastructure_info(domain: str) -> Dict[str, Any]:
    """Enhanced infrastructure gathering with ASN and reverse DNS"""
    try:
        ip = socket.gethostbyname(domain)
        
        # Get geolocation and ISP data
        geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        
        # Get ASN information
        asn_info = {}
        try:
            asn_res = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=5)
            if asn_res.status_code == 200:
                asn_data = asn_res.text.strip().split(',')
                if len(asn_data) >= 2:
                    asn_info = {
                        "number": asn_data[0].strip().replace('"', ''),
                        "organization": asn_data[1].strip().replace('"', '') if len(asn_data) > 1 else "Unknown"
                    }
        except:
            pass
        
        # Reverse DNS
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "No PTR record"
        
        return {
            "ip": ip,
            "status": "ONLINE",
            "reverse_dns": reverse_dns,
            "asn": asn_info,
            "provider": geo_res.get("isp", "Unknown"),
            "organization": geo_res.get("org", "Unknown"),
            "location": {
                "city": geo_res.get("city", "Unknown"),
                "region": geo_res.get("regionName", "Unknown"),
                "country": geo_res.get("country", "Unknown"),
                "coordinates": f"{geo_res.get('lat', 0)}, {geo_res.get('lon', 0)}"
            }
        }
    except socket.gaierror:
        return {
            "ip": "Resolution Failed",
            "status": "OFFLINE",
            "error": "DNS resolution failed - domain may not exist"
        }
    except Exception as e:
        return {
            "ip": "Unknown",
            "status": "ERROR",
            "error": str(e)
        }

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Comprehensive DNS record retrieval"""
    dns_data = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_data[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            dns_data[record_type] = []
        except dns.resolver.NXDOMAIN:
            dns_data[record_type] = ["Domain does not exist"]
            break
        except Exception:
            dns_data[record_type] = ["Query failed"]
    
    return dns_data

def get_subdomains_passive(domain: str) -> Dict[str, Any]:
    """Passive subdomain enumeration from multiple sources"""
    subdomains = set()
    sources_used = []
    
    # 1. Certificate Transparency (crt.sh)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                for subdomain in name.split('\n'):
                    clean_sub = subdomain.strip().lower()
                    if domain in clean_sub and '*' not in clean_sub:
                        subdomains.add(clean_sub)
            sources_used.append("crt.sh")
    except:
        pass
    
    # 2. HackerTarget API
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.split('\n'):
                if line and ',' in line:
                    subdomain = line.split(',')[0].strip()
                    subdomains.add(subdomain)
            sources_used.append("HackerTarget")
    except:
        pass
    
    # Sort and return
    subdomain_list = sorted(list(subdomains))
    
    return {
        "count": len(subdomain_list),
        "subdomains": subdomain_list[:50],  # Limit to 50 for display
        "sources": sources_used,
        "note": f"Showing {min(50, len(subdomain_list))} of {len(subdomain_list)} found" if len(subdomain_list) > 50 else "All results shown"
    }

def get_security_headers(domain: str) -> Dict[str, Any]:
    """Comprehensive security header analysis"""
    try:
        # Try HTTPS first
        try:
            response = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
            protocol = "HTTPS"
        except:
            response = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            protocol = "HTTP"
        
        headers = response.headers
        
        security_headers = {
            "strict-transport-security": headers.get("Strict-Transport-Security", "MISSING"),
            "content-security-policy": headers.get("Content-Security-Policy", "MISSING"),
            "x-frame-options": headers.get("X-Frame-Options", "MISSING"),
            "x-content-type-options": headers.get("X-Content-Type-Options", "MISSING"),
            "x-xss-protection": headers.get("X-XSS-Protection", "MISSING"),
            "referrer-policy": headers.get("Referrer-Policy", "MISSING"),
            "permissions-policy": headers.get("Permissions-Policy", "MISSING")
        }
        
        return {
            "server": headers.get("Server", "Hidden/Not Disclosed"),
            "powered_by": headers.get("X-Powered-By", "Not Disclosed"),
            "protocol": protocol,
            "status_code": response.status_code,
            "security": security_headers,
            "cookies": len(response.cookies),
            "redirect_chain": [str(r.url) for r in response.history] if response.history else ["No redirects"]
        }
    except Exception as e:
        return {
            "error": f"Unable to retrieve headers: {str(e)}",
            "server": "Unreachable",
            "security": {}
        }

def get_ssl_certificate(domain: str) -> Dict[str, Any]:
    """SSL/TLS certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Parse Subject Alternative Names
                san_list = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_list = [str(name) for name in san_ext.value]
                except:
                    pass
                
                return {
                    "issuer": cert.issuer.rfc4514_string(),
                    "subject": cert.subject.rfc4514_string(),
                    "version": cert.version.name,
                    "serial_number": str(cert.serial_number),
                    "valid_from": cert.not_valid_before.isoformat(),
                    "valid_until": cert.not_valid_after.isoformat(),
                    "days_remaining": (cert.not_valid_after - datetime.now()).days,
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                    "subject_alternative_names": san_list[:10],  # Limit to 10
                    "tls_version": ssock.version()
                }
    except Exception as e:
        return {
            "error": f"SSL certificate unavailable: {str(e)}",
            "status": "No HTTPS or certificate error"
        }

def get_whois_data(domain: str) -> Dict[str, Any]:
    """WHOIS information with better parsing"""
    try:
        w = whois.whois(domain)
        
        # Handle dates
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        return {
            "registrar": w.registrar or "Not Available",
            "creation_date": creation_date.isoformat() if creation_date else "Unknown",
            "expiration_date": expiration_date.isoformat() if expiration_date else "Unknown",
            "updated_date": w.updated_date[0].isoformat() if isinstance(w.updated_date, list) and w.updated_date else "Unknown",
            "status": w.status if isinstance(w.status, str) else (w.status[0] if w.status else "Unknown"),
            "name_servers": w.name_servers if w.name_servers else [],
            "organization": w.org or "Private/Redacted",
            "registrant_country": w.country or "Private/Redacted",
            "dnssec": w.dnssec or "Unsigned"
        }
    except Exception as e:
        return {
            "error": f"WHOIS lookup failed: {str(e)}",
            "note": "Domain may use privacy protection"
        }

def get_wayback_data(domain: str) -> Dict[str, Any]:
    """FIXED: Wayback Machine archive data with better error handling"""
    try:
        # Get latest snapshot
        url = f"http://archive.org/wayback/available?url={domain}"
        response = requests.get(url, timeout=15)
        
        if response.status_code != 200:
            return {"available": False, "message": "Wayback Machine API unavailable"}
        
        data = response.json()
        
        result = {}
        
        if 'archived_snapshots' in data and data['archived_snapshots']:
            closest = data['archived_snapshots'].get('closest', {})
            
            if not closest:
                return {"available": False, "message": "No archives found in Wayback Machine"}
            
            result['available'] = True
            result['archive_url'] = closest.get('url', '')
            result['last_snapshot'] = closest.get('timestamp', '')
            result['status_code'] = closest.get('status', '')
            
            # Get total snapshots count - SIMPLIFIED AND FIXED
            try:
                # Use the CDX API to get a count
                cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1"
                cdx_response = requests.get(cdx_url, timeout=10)
                
                if cdx_response.status_code == 200:
                    cdx_data = cdx_response.json()
                    if isinstance(cdx_data, list) and len(cdx_data) > 0:
                        # Now get the actual count
                        count_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&showNumPages=true"
                        count_response = requests.get(count_url, timeout=10)
                        
                        if count_response.status_code == 200 and count_response.text.strip().isdigit():
                            result['total_snapshots'] = count_response.text.strip()
                        else:
                            result['total_snapshots'] = "Available"
                    else:
                        result['total_snapshots'] = "1+"
                else:
                    result['total_snapshots'] = "Available"
            except Exception as e:
                print(f"[WARNING] Could not get snapshot count: {e}")
                result['total_snapshots'] = "Available"
            
            # Format timestamp for readability
            if result['last_snapshot']:
                try:
                    ts = result['last_snapshot']
                    if len(ts) >= 14:
                        formatted_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
                        result['last_snapshot_formatted'] = formatted_date
                    else:
                        result['last_snapshot_formatted'] = result['last_snapshot']
                except Exception as e:
                    print(f"[WARNING] Could not format timestamp: {e}")
                    result['last_snapshot_formatted'] = result['last_snapshot']
            
            return result
        else:
            return {"available": False, "message": "No archives found in Wayback Machine"}
            
    except requests.exceptions.Timeout:
        return {"available": False, "error": "Wayback Machine request timed out"}
    except requests.exceptions.RequestException as e:
        return {"available": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        print(f"[ERROR] Wayback lookup failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"available": False, "error": f"Archive lookup failed: {str(e)}"}

def get_technology_stack(domain: str) -> Dict[str, List[Dict[str, str]]]:
    """FIXED: Technology detection with proper structure for frontend"""
    try:
        wappalyzer = Wappalyzer.latest()
        
        # Try both HTTP and HTTPS
        webpage = None
        for protocol in ['https', 'http']:
            try:
                webpage = WebPage.new_from_url(f"{protocol}://{domain}", timeout=15)
                break
            except:
                continue
        
        if not webpage:
            return {"message": "Unable to connect to target"}
        
        # Get raw analysis
        raw_data = wappalyzer.analyze_with_versions_and_categories(webpage)
        
        if not raw_data:
            return {"message": "No technologies detected"}
        
        # Restructure data: Category -> List of {name, version}
        tech_by_category = {}
        
        for app_name, app_info in raw_data.items():
            # Get version - FIXED: Handle both dict and list types
            version = "Undetected"
            categories = ["Miscellaneous"]
            
            if isinstance(app_info, dict):
                # Handle dictionary format
                versions = app_info.get("versions", [])
                if versions and len(versions) > 0:
                    version = versions[0]
                categories = app_info.get("categories", ["Miscellaneous"])
            elif isinstance(app_info, list):
                # Handle list format - check if it contains version info
                if len(app_info) > 0:
                    if isinstance(app_info[0], str):
                        version = app_info[0]
                    elif isinstance(app_info[0], dict) and "version" in app_info[0]:
                        version = app_info[0]["version"]
                # Categories might be in second element
                if len(app_info) > 1 and isinstance(app_info[1], list):
                    categories = app_info[1]
            
            # Ensure categories is a list
            if not isinstance(categories, list):
                categories = [str(categories)]
            
            # Add to each category
            for category in categories:
                if category not in tech_by_category:
                    tech_by_category[category] = []
                
                tech_by_category[category].append({
                    "name": app_name,
                    "version": version
                })
        
        # Sort categories alphabetically
        return dict(sorted(tech_by_category.items()))
        
    except Exception as e:
        print(f"[ERROR] Technology detection failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": f"Technology detection failed: {str(e)}"}

def calculate_risk_score(data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate comprehensive risk score"""
    score = 0
    issues = []
    recommendations = []
    
    # Check security headers
    headers = data.get("fingerprint", {})
    if isinstance(headers, dict) and "security" in headers:
        sec = headers["security"]
        
        if sec.get("strict-transport-security") == "MISSING":
            score += 20
            issues.append("No HSTS Policy")
            recommendations.append("Enable HTTP Strict Transport Security")
        
        if sec.get("content-security-policy") == "MISSING":
            score += 15
            issues.append("No CSP Header")
            recommendations.append("Implement Content Security Policy")
        
        if sec.get("x-frame-options") == "MISSING":
            score += 10
            issues.append("No X-Frame-Options")
            recommendations.append("Add X-Frame-Options to prevent clickjacking")
        
        if sec.get("x-content-type-options") == "MISSING":
            score += 5
            issues.append("No X-Content-Type-Options")
            recommendations.append("Set X-Content-Type-Options: nosniff")
    
    # Check if server header is exposed
    if headers.get("server") and headers["server"] not in ["Hidden/Not Disclosed", "Unreachable"]:
        score += 10
        issues.append(f"Server Banner Exposed: {headers['server']}")
        recommendations.append("Hide server version information")
    
    # Check SSL certificate
    ssl_data = data.get("ssl_certificate", {})
    if "error" in ssl_data:
        score += 25
        issues.append("No HTTPS/SSL Certificate")
        recommendations.append("Implement SSL/TLS certificate")
    elif ssl_data.get("days_remaining", 9999) < 30:
        score += 15
        issues.append(f"SSL Certificate Expiring Soon ({ssl_data.get('days_remaining')} days)")
        recommendations.append("Renew SSL certificate")
    
    # Check protocol
    if headers.get("protocol") == "HTTP":
        score += 20
        issues.append("Site accessible via HTTP")
        recommendations.append("Force HTTPS redirect")
    
    # Determine risk level
    if score == 0:
        level = "MINIMAL"
        status = "Excellent security posture"
    elif score < 30:
        level = "LOW"
        status = "Good security with minor improvements needed"
    elif score < 60:
        level = "MEDIUM"
        status = "Moderate security concerns detected"
    elif score < 80:
        level = "HIGH"
        status = "Significant security vulnerabilities found"
    else:
        level = "CRITICAL"
        status = "Critical security issues require immediate attention"
    
    return {
        "score": min(score, 100),
        "level": level,
        "status": status,
        "issues": issues,
        "recommendations": recommendations,
        "issues_count": len(issues)
    }

# ==================== MAIN API ENDPOINT ====================

@app.get("/api/v1/recon/{domain}")
async def run_recon(domain: str):
    """
    Comprehensive passive reconnaissance scan
    """
    try:
        # Normalize domain
        clean_domain = normalize_domain(domain)
        
        # Get historical data
        history = get_scan_history(clean_domain)
        
        # Run all reconnaissance modules
        print(f"[*] Starting reconnaissance on: {clean_domain}")
        
        infrastructure = get_infrastructure_info(clean_domain)
        dns_records = get_dns_records(clean_domain)
        subdomains = get_subdomains_passive(clean_domain)
        fingerprint = get_security_headers(clean_domain)
        ssl_cert = get_ssl_certificate(clean_domain)
        whois_data = get_whois_data(clean_domain)
        wayback = get_wayback_data(clean_domain)
        technology = get_technology_stack(clean_domain)
        
        # Compile results
        recon_data = {
            "target": clean_domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "infrastructure": infrastructure,
            "dns": dns_records,
            "subdomains": subdomains,
            "fingerprint": fingerprint,
            "ssl_certificate": ssl_cert,
            "whois": whois_data,
            "wayback": wayback,
            "technology": technology,
            "history_correlation": history
        }
        
        # Calculate risk after all data is collected
        risk_assessment = calculate_risk_score(recon_data)
        recon_data["risk_score"] = risk_assessment["score"]
        recon_data["risk_level"] = risk_assessment["level"]
        recon_data["risk_status"] = risk_assessment["status"]
        recon_data["risk_issues"] = risk_assessment["issues"]
        recon_data["recommendations"] = risk_assessment["recommendations"]
        
        # Save to database
        conn = sqlite3.connect('recon_history.db')
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (domain, data, scan_count) 
            VALUES (?, ?, 1)
            ON CONFLICT(domain) 
            DO UPDATE SET 
                data = excluded.data, 
                timestamp = CURRENT_TIMESTAMP,
                scan_count = scan_count + 1
        """, (clean_domain, json.dumps(recon_data)))
        conn.commit()
        conn.close()
        
        print(f"[✓] Reconnaissance completed for: {clean_domain}")
        return recon_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reconnaissance failed: {str(e)}")

@app.get("/api/v1/history")
async def get_history():
    """Get all scan history"""
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    c.execute("SELECT domain, timestamp, scan_count FROM scans ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    
    return {
        "scans": [
            {"domain": row[0], "last_scan": row[1], "total_scans": row[2]}
            for row in rows
        ]
    }

@app.get("/api/v1/report/{domain}")
def generate_report(domain: str):
    """Full Intelligence Report generation encompassing all dashboard data"""
    clean_domain = normalize_domain(domain)
    
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    c.execute("SELECT data FROM scans WHERE domain=?", (clean_domain,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Domain not scanned yet")

    try:
        data = json.loads(row[0])
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- Helper for Character Encoding Safety ---
        def safe_text(text):
            return str(text).encode('latin-1', 'replace').decode('latin-1')
        
        # --- HEADER ---
        pdf.set_fill_color(15, 15, 15)
        pdf.rect(0, 0, 210, 50, 'F')
        pdf.set_font("Arial", 'B', 28)
        pdf.set_text_color(0, 127, 255)
        pdf.cell(0, 25, "CORERECON INTELLIGENCE", ln=True, align='C')
        pdf.set_text_color(180, 180, 180)
        pdf.set_font("Arial", size=11)
        pdf.cell(0, 10, safe_text(f"Target Assessment Report: {clean_domain}"), ln=True, align='C')
        pdf.cell(0, 10, f"Generated: {data.get('timestamp')}", ln=True, align='C')
        pdf.ln(10)

        # --- 1. EXECUTIVE SUMMARY & RISK ---
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", 'B', 14)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(0, 10, " 1. EXECUTIVE RISK ASSESSMENT", ln=True, fill=True)
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, f"Overall Risk Score: {data.get('risk_score', 0)}/100 ({data.get('risk_level', 'UNKNOWN')})", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 6, f"Summary: {data.get('risk_status', 'N/A')}")
        
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 8, "Critical Issues Identified:", ln=True)
        pdf.set_font("Arial", size=9)
        for issue in data.get('risk_issues', []):
            pdf.cell(0, 5, safe_text(f"  [!] {issue}"), ln=True)

        # --- 2. INFRASTRUCTURE & NETWORK ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 2. INFRASTRUCTURE & NETWORK", ln=True, fill=True)
        infra = data.get("infrastructure", {})
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 6, f"Primary IP: {infra.get('ip', 'N/A')}", ln=True)
        pdf.cell(0, 6, f"ISP/Provider: {safe_text(infra.get('provider', 'N/A'))}", ln=True)
        pdf.cell(0, 6, f"Reverse DNS: {safe_text(infra.get('reverse_dns', 'N/A'))}", ln=True)
        loc = infra.get('location', {})
        pdf.cell(0, 6, f"Location: {loc.get('city')}, {loc.get('country')} ({loc.get('coordinates')})", ln=True)

        # --- 3. SYSTEM FINGERPRINT & HEADERS ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 3. SYSTEM FINGERPRINT", ln=True, fill=True)
        fing = data.get("fingerprint", {})
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 6, f"Server Header: {safe_text(fing.get('server', 'Hidden'))}", ln=True)
        pdf.cell(0, 6, f"Protocol: {fing.get('protocol', 'N/A')}", ln=True)
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 6, "Security Headers Status:", ln=True)
        pdf.set_font("Courier", size=9)
        for head, val in fing.get('security', {}).items():
            status = "SET" if val != "MISSING" else "MISSING"
            pdf.cell(0, 5, f"{head.upper():<30} : {status}", ln=True)

        # --- 4. SSL CERTIFICATE DETAILS ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 4. SSL/TLS CERTIFICATE", ln=True, fill=True)
        ssl_data = data.get("ssl_certificate", {})
        if "error" not in ssl_data:
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 6, safe_text(f"Issuer: {ssl_data.get('issuer')}"), ln=True)
            pdf.cell(0, 6, f"Signature Algorithm: {ssl_data.get('signature_algorithm')}", ln=True)
            pdf.cell(0, 6, f"Valid Until: {ssl_data.get('valid_until')}", ln=True)
            pdf.cell(0, 6, f"Days Remaining: {ssl_data.get('days_remaining')}", ln=True)
        else:
            pdf.cell(0, 6, "No SSL/TLS data available for this target", ln=True)

        # --- 5. DNS RECORDS ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 5. DNS RECORDS", ln=True, fill=True)
        pdf.set_font("Courier", size=9)
        for r_type, records in data.get("dns", {}).items():
            if records and isinstance(records, list):
                pdf.set_font("Courier", 'B', 9)
                pdf.cell(0, 6, f"[{r_type} Records]", ln=True)
                pdf.set_font("Courier", size=8)
                for r in records:
                    pdf.cell(0, 4, f"  > {safe_text(r)}", ln=True)

        # --- 6. WHOIS DATA ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 6. WHOIS INFORMATION", ln=True, fill=True)
        whois_data = data.get("whois", {})
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 6, f"Registrar: {safe_text(whois_data.get('registrar'))}", ln=True)
        pdf.cell(0, 6, f"Organization: {safe_text(whois_data.get('organization'))}", ln=True)
        pdf.cell(0, 6, f"Creation Date: {whois_data.get('creation_date')}", ln=True)
        pdf.cell(0, 6, f"Expiration Date: {whois_data.get('expiration_date')}", ln=True)

        # --- 7. ADAPTABLE TECHNOLOGY STACK (SAFE VERSION) ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 7. TECHNOLOGY STACK ASSESSMENT", ln=True, fill=True)
        
        tech_data = data.get("technology", {})
        
        # FIX: Check if tech_data is actually a dictionary before calling .items()
        if isinstance(tech_data, dict) and "Message" not in tech_data and "error" not in tech_data:
            for category, items in tech_data.items():
                if pdf.get_y() > 250:
                    pdf.add_page()
                
                pdf.ln(2)
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(0, 80, 160)
                pdf.cell(0, 6, safe_text(str(category).upper()), ln=True)
                
                pdf.set_text_color(60, 60, 60)
                pdf.set_font("Arial", size=9)
                
                # Ensure 'items' is a list of dicts (new format) or a list of strings (old format)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            # New format: {"name": "...", "version": "..."}
                            name = item.get('name', 'Unknown')
                            ver = item.get('version', 'Undetected')
                            tech_line = f"  [-] {name} (Version: {ver})"
                        else:
                            # Old format fallback: just a string
                            tech_line = f"  [-] {str(item)}"
                        pdf.cell(0, 5, safe_text(tech_line), ln=True)
            pdf.set_text_color(0, 0, 0)
            
        elif isinstance(tech_data, list):
            # FALLBACK: If the data in the DB is still an old-style flat list
            pdf.set_font("Arial", size=9)
            for item in tech_data:
                pdf.cell(0, 5, safe_text(f"  [-] {str(item)}"), ln=True)
        else:
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 6, "  [!] No identifiable technology signatures found.", ln=True)
        
        # --- 8. SUBDOMAINS ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 8. SUBDOMAIN DISCOVERY", ln=True, fill=True)
        subs = data.get("subdomains", {})
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 6, f"Total Subdomains Found: {subs.get('count', 0)}", ln=True)
        pdf.set_font("Courier", size=8)
        # Displaying first 40 subdomains in columns
        sub_list = subs.get('subdomains', [])
        for i in range(0, len(sub_list[:40]), 2):
            line = f"  • {sub_list[i]:<40}"
            if i+1 < len(sub_list):
                line += f"  • {sub_list[i+1]}"
            pdf.cell(0, 4, safe_text(line), ln=True)

        # --- 9. WEB ARCHIVES ---
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 9. WEB ARCHIVE HISTORY", ln=True, fill=True)
        wb = data.get("wayback", {})
        pdf.set_font("Arial", size=10)
        if wb.get('available'):
            pdf.cell(0, 6, f"Total Snapshots: {wb.get('total_snapshots')}", ln=True)
            pdf.cell(0, 6, f"Last Captured: {wb.get('last_snapshot')}", ln=True)
            pdf.set_font("Arial", 'I', 8)
            pdf.multi_cell(0, 5, f"Archive URL: {wb.get('archive_url')}")
        else:
            pdf.cell(0, 6, "No historical archives found.", ln=True)

        pdf_output = pdf.output(dest='S').encode('latin-1')
        headers = {
            'Content-Disposition': f'attachment; filename="CoreRecon_Intel_{clean_domain}.pdf"'
        }
        return Response(content=pdf_output, headers=headers, media_type='application/pdf')

    except Exception as e:
        print(f"REPORT ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Report failed: {str(e)}")

@app.get("/")
async def root():
    return {
        "service": "CoreRecon Intelligence API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "scan": "/api/v1/recon/{domain}",
            "report": "/api/v1/report/{domain}",
            "history": "/api/v1/history"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)