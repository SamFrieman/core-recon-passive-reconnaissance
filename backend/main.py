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
    """Full Intelligence Report generation with sleek, modern design"""
    # Sanitize the domain input
    try:
        clean_domain = sanitize_input(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Try to find the scan data - be flexible with domain format
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    
    # First try exact match
    c.execute("SELECT data FROM scans WHERE domain=?", (clean_domain,))
    row = c.fetchone()
    
    # If not found, try with www prefix removed/added
    if not row:
        if clean_domain.startswith('www.'):
            alt_domain = clean_domain[4:]
        else:
            alt_domain = 'www.' + clean_domain
        c.execute("SELECT data FROM scans WHERE domain=?", (alt_domain,))
        row = c.fetchone()
    
    # If still not found, try without protocol
    if not row:
        normalized = clean_domain.replace('http://', '').replace('https://', '').replace('www.', '').strip('/')
        c.execute("SELECT data FROM scans WHERE domain LIKE ?", (f"%{normalized}%",))
        row = c.fetchone()
    
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404, 
            detail=f"Domain '{clean_domain}' not found in scan history. Please run a scan first."
        )

    try:
        data = json.loads(row[0])
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- Helper Functions ---
        def safe_text(text):
            """Safely encode text for PDF"""
            return str(text).encode('latin-1', 'replace').decode('latin-1')
        
        def add_header_bar(title, y_position=None):
            """Add a sleek header bar with gradient effect"""
            if y_position:
                pdf.set_y(y_position)
            pdf.set_fill_color(20, 30, 40)  # Dark blue-gray
            pdf.rect(10, pdf.get_y(), 190, 10, 'F')
            pdf.set_text_color(0, 200, 255)  # Cyan
            pdf.set_font("Arial", 'B', 12)
            pdf.set_xy(15, pdf.get_y() + 2)
            pdf.cell(0, 6, title, ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
        
        def add_key_value(key, value, highlight=False):
            """Add a key-value pair with styling"""
            pdf.set_font("Arial", 'B', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(50, 5, safe_text(key + ":"), ln=False)
            
            if highlight:
                pdf.set_text_color(0, 150, 200)  # Cyan for important values
                pdf.set_font("Arial", 'B', 9)
            else:
                pdf.set_text_color(60, 60, 60)
                pdf.set_font("Arial", '', 9)
            
            pdf.cell(0, 5, safe_text(str(value)), ln=True)
            pdf.set_text_color(0, 0, 0)
        
        def add_status_badge(label, status, is_good):
            """Add a status badge with color coding"""
            pdf.set_font("Arial", 'B', 8)
            if is_good:
                pdf.set_fill_color(0, 180, 100)  # Green
            else:
                pdf.set_fill_color(255, 80, 80)  # Red
            pdf.set_text_color(255, 255, 255)
            pdf.cell(45, 5, safe_text(label), 0, 0, 'C', True)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(45, 5, safe_text(status), 0, 1, 'C', True)
            pdf.set_text_color(0, 0, 0)
        
        def add_divider():
            """Add a subtle divider line"""
            pdf.set_draw_color(200, 200, 200)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)
        
        # ============================================================
        # COVER PAGE - Sleek and Modern
        # ============================================================
        
        # Dark gradient background effect (simulated with rectangles)
        pdf.set_fill_color(15, 20, 30)
        pdf.rect(0, 0, 210, 297, 'F')
        
        # Top accent bar
        pdf.set_fill_color(0, 200, 255)
        pdf.rect(0, 0, 210, 3, 'F')
        
        # Logo area (shield icon simulation)
        pdf.set_xy(85, 60)
        pdf.set_fill_color(0, 150, 200)
        pdf.rect(85, 60, 40, 40, 'F')
        pdf.set_font("Arial", 'B', 30)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(85, 75)
        pdf.cell(40, 10, "CR", 0, 0, 'C')
        
        # Main title
        pdf.set_xy(0, 120)
        pdf.set_font("Arial", 'B', 36)
        pdf.set_text_color(0, 200, 255)
        pdf.cell(0, 15, "CORERECON", ln=True, align='C')
        
        pdf.set_font("Arial", '', 14)
        pdf.set_text_color(180, 180, 180)
        pdf.cell(0, 8, "INTELLIGENCE REPORT", ln=True, align='C')
        
        # Target info box
        pdf.set_xy(40, 160)
        pdf.set_fill_color(30, 40, 50)
        pdf.rect(40, 160, 130, 30, 'F')
        
        pdf.set_xy(40, 165)
        pdf.set_font("Arial", 'B', 11)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(130, 6, "TARGET DOMAIN", 0, 1, 'C')
        
        pdf.set_xy(40, 172)
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(0, 200, 255)
        pdf.cell(130, 8, safe_text(data.get('target', clean_domain)), 0, 1, 'C')
        
        # Metadata
        pdf.set_xy(0, 210)
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(140, 140, 140)
        pdf.cell(0, 5, f"Report Generated: {data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", ln=True, align='C')
        pdf.cell(0, 5, "Classification: TLP:WHITE - For Authorized Use Only", ln=True, align='C')
        
        # Bottom accent
        pdf.set_fill_color(0, 200, 255)
        pdf.rect(0, 294, 210, 3, 'F')
        
        # Footer
        pdf.set_xy(0, 280)
        pdf.set_font("Arial", 'I', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, "Powered by CoreRecon Intelligence Platform v1.0", ln=True, align='C')
        
        # ============================================================
        # PAGE 2 - EXECUTIVE SUMMARY
        # ============================================================
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        
        # Page header
        pdf.set_font("Arial", 'B', 20)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 10, "EXECUTIVE SUMMARY", ln=True)
        pdf.set_draw_color(0, 200, 255)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)
        
        # Risk Score - Large visual display
        risk_score = data.get('risk_score', 0)
        risk_level = data.get('risk_level', 'UNKNOWN')
        
        pdf.set_fill_color(245, 245, 250)
        pdf.rect(10, pdf.get_y(), 190, 45, 'F')
        
        pdf.set_xy(20, pdf.get_y() + 8)
        pdf.set_font("Arial", '', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, "OVERALL THREAT LEVEL", ln=True)
        
        pdf.set_x(20)
        pdf.set_font("Arial", 'B', 32)
        
        # Color code the risk level
        if risk_level in ['MINIMAL', 'LOW']:
            pdf.set_text_color(0, 180, 100)
        elif risk_level == 'MEDIUM':
            pdf.set_text_color(255, 160, 0)
        else:
            pdf.set_text_color(255, 60, 60)
        
        pdf.cell(50, 12, f"{risk_score}/100", ln=False)
        
        pdf.set_font("Arial", 'B', 24)
        pdf.cell(0, 12, risk_level, ln=True)
        
        pdf.set_x(20)
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, safe_text(data.get('risk_status', 'Assessment complete')))
        
        pdf.ln(5)
        add_divider()
        
        # Critical Issues Section
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(255, 60, 60)
        issues = data.get('risk_issues', [])
        pdf.cell(0, 7, f"CRITICAL FINDINGS ({len(issues)})", ln=True)
        
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(60, 60, 60)
        
        if issues:
            for i, issue in enumerate(issues, 1):
                pdf.set_fill_color(255, 245, 245)
                pdf.rect(15, pdf.get_y(), 180, 8, 'F')
                pdf.set_xy(18, pdf.get_y() + 2)
                pdf.cell(10, 4, f"{i}.", ln=False)
                pdf.multi_cell(165, 4, safe_text(issue))
        else:
            pdf.set_fill_color(240, 255, 240)
            pdf.rect(15, pdf.get_y(), 180, 8, 'F')
            pdf.set_xy(18, pdf.get_y() + 2)
            pdf.set_text_color(0, 150, 100)
            pdf.cell(0, 4, "No critical vulnerabilities detected", ln=True)
        
        pdf.ln(5)
        add_divider()
        
        # Recommendations
        recommendations = data.get('recommendations', [])
        if recommendations:
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 7, f"SECURITY RECOMMENDATIONS ({len(recommendations)})", ln=True)
            
            pdf.set_font("Arial", '', 9)
            pdf.set_text_color(60, 60, 60)
            
            for i, rec in enumerate(recommendations[:5], 1):
                pdf.set_fill_color(240, 250, 255)
                pdf.rect(15, pdf.get_y(), 180, 8, 'F')
                pdf.set_xy(18, pdf.get_y() + 2)
                pdf.cell(10, 4, f"{i}.", ln=False)
                pdf.multi_cell(165, 4, safe_text(rec))
        
        # ============================================================
        # PAGE 3 - INFRASTRUCTURE & NETWORK
        # ============================================================
        pdf.add_page()
        add_header_bar("01. INFRASTRUCTURE & NETWORK INTELLIGENCE")
        
        infra = data.get("infrastructure", {})
        
        # Status indicator
        status = infra.get('status', 'UNKNOWN')
        if status == 'ONLINE':
            pdf.set_fill_color(0, 180, 100)
        else:
            pdf.set_fill_color(255, 80, 80)
        
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(40, 7, f"STATUS: {status}", 0, 1, 'C', True)
        pdf.ln(3)
        
        pdf.set_text_color(0, 0, 0)
        
        # Network details in a clean grid
        add_key_value("Primary IP Address", infra.get('ip', 'N/A'), True)
        add_key_value("Reverse DNS", infra.get('reverse_dns', 'N/A'))
        
        if infra.get('asn'):
            add_key_value("ASN Number", infra['asn'].get('number', 'N/A'))
            add_key_value("ASN Organization", infra['asn'].get('organization', 'N/A'))
        
        add_key_value("ISP Provider", infra.get('provider', 'N/A'))
        add_key_value("Organization", infra.get('organization', 'N/A'))
        
        pdf.ln(3)
        add_divider()
        
        # Geographic location
        loc = infra.get('location', {})
        if loc:
            pdf.set_font("Arial", 'B', 10)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 6, "GEOGRAPHIC LOCATION", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            
            add_key_value("City", loc.get('city', 'Unknown'))
            add_key_value("Region", loc.get('region', 'Unknown'))
            add_key_value("Country", loc.get('country', 'Unknown'))
            add_key_value("Coordinates", loc.get('coordinates', 'N/A'))
        
        # ============================================================
        # PAGE 4 - SYSTEM FINGERPRINT
        # ============================================================
        pdf.add_page()
        add_header_bar("02. SYSTEM FINGERPRINT & SECURITY HEADERS")
        
        fing = data.get("fingerprint", {})
        
        add_key_value("Web Server", fing.get('server', 'Hidden/Unknown'))
        add_key_value("Protocol", fing.get('protocol', 'N/A'), True)
        add_key_value("HTTP Status", fing.get('status_code', 'N/A'))
        add_key_value("Powered By", fing.get('powered_by', 'Not Disclosed'))
        add_key_value("Cookies Set", fing.get('cookies', 0))
        
        pdf.ln(3)
        add_divider()
        
        # Security headers in a clean table format
        pdf.set_font("Arial", 'B', 10)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 6, "SECURITY HEADER ANALYSIS", ln=True)
        pdf.ln(2)
        
        # Table header
        pdf.set_fill_color(240, 240, 245)
        pdf.set_font("Arial", 'B', 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(120, 6, "Security Header", 1, 0, 'L', True)
        pdf.cell(60, 6, "Status", 1, 1, 'C', True)
        
        # Table rows
        pdf.set_font("Arial", '', 8)
        for head, val in fing.get('security', {}).items():
            pdf.cell(120, 5, safe_text(head.replace('-', ' ').upper()), 1, 0, 'L')
            
            if val == "MISSING":
                pdf.set_fill_color(255, 240, 240)
                pdf.set_text_color(200, 50, 50)
            else:
                pdf.set_fill_color(240, 255, 240)
                pdf.set_text_color(0, 150, 100)
            
            pdf.cell(60, 5, "MISSING" if val == "MISSING" else "CONFIGURED", 1, 1, 'C', True)
            pdf.set_text_color(60, 60, 60)
        
        # ============================================================
        # PAGE 5 - SSL CERTIFICATE
        # ============================================================
        pdf.add_page()
        add_header_bar("03. SSL/TLS CERTIFICATE INFORMATION")
        
        ssl_data = data.get("ssl_certificate", {})
        
        if "error" not in ssl_data:
            days_remaining = ssl_data.get('days_remaining', 0)
            
            # Certificate validity status
            if days_remaining > 30:
                pdf.set_fill_color(0, 180, 100)
                status_text = "VALID"
            elif days_remaining > 0:
                pdf.set_fill_color(255, 160, 0)
                status_text = "EXPIRING SOON"
            else:
                pdf.set_fill_color(255, 60, 60)
                status_text = "EXPIRED"
            
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(60, 7, f"CERTIFICATE: {status_text}", 0, 0, 'C', True)
            pdf.set_fill_color(240, 240, 245)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(60, 7, f"{days_remaining} Days Remaining", 0, 1, 'C', True)
            pdf.ln(5)
            
            pdf.set_text_color(0, 0, 0)
            
            add_key_value("TLS Version", ssl_data.get('tls_version', 'N/A'), True)
            add_key_value("Signature Algorithm", ssl_data.get('signature_algorithm', 'N/A'))
            add_key_value("Serial Number", ssl_data.get('serial_number', 'N/A'))
            
            pdf.ln(2)
            add_divider()
            
            pdf.set_font("Arial", 'B', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, "ISSUER:", ln=True)
            pdf.set_font("Courier", '', 7)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 4, safe_text(ssl_data.get('issuer', 'N/A')))
            
            pdf.ln(2)
            
            pdf.set_font("Arial", 'B', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, "SUBJECT:", ln=True)
            pdf.set_font("Courier", '', 7)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 4, safe_text(ssl_data.get('subject', 'N/A')))
            
            pdf.ln(2)
            add_divider()
            
            add_key_value("Valid From", ssl_data.get('valid_from', 'N/A'))
            add_key_value("Valid Until", ssl_data.get('valid_until', 'N/A'))
            
            # Subject Alternative Names
            sans = ssl_data.get('subject_alternative_names', [])
            if sans:
                pdf.ln(2)
                pdf.set_font("Arial", 'B', 9)
                pdf.set_text_color(0, 150, 200)
                pdf.cell(0, 5, f"SUBJECT ALTERNATIVE NAMES ({len(sans)})", ln=True)
                pdf.set_font("Courier", '', 7)
                pdf.set_text_color(60, 60, 60)
                for san in sans[:15]:
                    pdf.cell(0, 3, f"  > {safe_text(san)}", ln=True)
        else:
            pdf.set_fill_color(255, 240, 240)
            pdf.rect(15, pdf.get_y(), 180, 20, 'F')
            pdf.set_xy(20, pdf.get_y() + 7)
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(200, 50, 50)
            pdf.cell(0, 6, "No SSL/TLS certificate detected for this target", ln=True)
        
        # ============================================================
        # PAGE 6 - DNS RECORDS
        # ============================================================
        pdf.add_page()
        add_header_bar("04. DNS RECORDS & CONFIGURATION")
        
        dns_data = data.get("dns", {})
        
        for r_type, records in dns_data.items():
            if records and isinstance(records, list) and len(records) > 0:
                if "Query failed" in records[0] or "timeout" in records[0]:
                    continue
                
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(0, 150, 200)
                pdf.cell(0, 6, f"{r_type} RECORDS ({len(records)})", ln=True)
                pdf.ln(1)
                
                pdf.set_fill_color(245, 245, 250)
                pdf.rect(15, pdf.get_y(), 180, 5 + (len(records[:10]) * 4), 'F')
                
                pdf.set_font("Courier", '', 8)
                pdf.set_text_color(60, 60, 60)
                pdf.set_x(18)
                
                for record in records[:10]:
                    pdf.set_x(18)
                    pdf.cell(0, 4, safe_text(f"> {record}"), ln=True)
                
                if len(records) > 10:
                    pdf.set_x(18)
                    pdf.set_font("Arial", 'I', 7)
                    pdf.set_text_color(120, 120, 120)
                    pdf.cell(0, 4, f"... and {len(records) - 10} more records", ln=True)
                
                pdf.ln(4)
        
        # ============================================================
        # PAGE 7 - WHOIS DATA
        # ============================================================
        pdf.add_page()
        add_header_bar("05. WHOIS & DOMAIN REGISTRATION")
        
        whois_data = data.get("whois", {})
        
        if not whois_data.get('error'):
            add_key_value("Registrar", whois_data.get('registrar', 'N/A'), True)
            add_key_value("Organization", whois_data.get('organization', 'Private/Redacted'))
            add_key_value("Registrant Country", whois_data.get('registrant_country', 'Private/Redacted'))
            add_key_value("DNSSEC", whois_data.get('dnssec', 'Unsigned'))
            
            pdf.ln(3)
            add_divider()
            
            pdf.set_font("Arial", 'B', 10)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 6, "IMPORTANT DATES", ln=True)
            pdf.ln(2)
            
            add_key_value("Created", whois_data.get('creation_date', 'Unknown'))
            add_key_value("Last Updated", whois_data.get('updated_date', 'Unknown'))
            add_key_value("Expires", whois_data.get('expiration_date', 'Unknown'))
            
            # Name servers
            ns_list = whois_data.get('name_servers', [])
            if ns_list:
                pdf.ln(3)
                add_divider()
                
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(0, 150, 200)
                pdf.cell(0, 6, f"NAME SERVERS ({len(ns_list)})", ln=True)
                pdf.ln(2)
                
                pdf.set_font("Courier", '', 8)
                pdf.set_text_color(60, 60, 60)
                for ns in ns_list[:8]:
                    pdf.cell(0, 4, f"  > {safe_text(ns)}", ln=True)
        else:
            pdf.set_fill_color(255, 250, 240)
            pdf.rect(15, pdf.get_y(), 180, 15, 'F')
            pdf.set_xy(20, pdf.get_y() + 5)
            pdf.set_font("Arial", '', 9)
            pdf.set_text_color(180, 140, 0)
            pdf.multi_cell(0, 5, safe_text(whois_data.get('note', 'WHOIS data unavailable or privacy protected')))
        
        # ============================================================
        # PAGE 8 - TECHNOLOGY STACK
        # ============================================================
        pdf.add_page()
        add_header_bar("06. TECHNOLOGY STACK & WEB FRAMEWORK")
        
        tech_data = data.get("technology", {})
        
        if isinstance(tech_data, dict) and "message" not in tech_data and "error" not in tech_data:
            for category, items in tech_data.items():
                if pdf.get_y() > 250:
                    pdf.add_page()
                
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(0, 150, 200)
                pdf.cell(0, 6, f"{safe_text(str(category).upper())} ({len(items)})", ln=True)
                pdf.ln(1)
                
                pdf.set_fill_color(245, 245, 250)
                
                if isinstance(items, list):
                    for item in items[:15]:
                        pdf.rect(15, pdf.get_y(), 180, 6, 'F')
                        
                        if isinstance(item, dict):
                            name = item.get('name', 'Unknown')
                            ver = item.get('version', 'Undetected')
                            
                            pdf.set_xy(18, pdf.get_y() + 1.5)
                            pdf.set_font("Arial", 'B', 8)
                            pdf.set_text_color(60, 60, 60)
                            pdf.cell(100, 3, safe_text(name), ln=False)
                            
                            pdf.set_font("Courier", '', 7)
                            if ver != 'Undetected':
                                pdf.set_text_color(0, 150, 200)
                            else:
                                pdf.set_text_color(150, 150, 150)
                            pdf.cell(0, 3, safe_text(f"v{ver}"), ln=True)
                        else:
                            pdf.set_xy(18, pdf.get_y() + 1.5)
                            pdf.set_font("Arial", '', 8)
                            pdf.set_text_color(60, 60, 60)
                            pdf.cell(0, 3, safe_text(str(item)), ln=True)
                
                pdf.ln(3)
        else:
            pdf.set_fill_color(245, 245, 250)
            pdf.rect(15, pdf.get_y(), 180, 15, 'F')
            pdf.set_xy(20, pdf.get_y() + 5)
            pdf.set_font("Arial", '', 9)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 5, "No technology signatures identified", ln=True)
        
        # ============================================================
        # PAGE 9 - SUBDOMAINS
        # ============================================================
        pdf.add_page()
        add_header_bar("07. SUBDOMAIN DISCOVERY & ENUMERATION")
        
        subs = data.get("subdomains", {})
        sub_count = subs.get('count', 0)
        
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 8, f"{sub_count} SUBDOMAINS DISCOVERED", ln=True)
        pdf.ln(3)
        
        if subs.get('sources'):
            pdf.set_font("Arial", '', 8)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 4, f"Sources: {', '.join(subs['sources'])}", ln=True)
            pdf.ln(2)
        
        add_divider()
        
        sub_list = subs.get('subdomains', [])
        if sub_list:
            pdf.set_font("Courier", '', 7)
            pdf.set_text_color(60, 60, 60)
            
            # Display in two columns for space efficiency
            for i in range(0, min(len(sub_list), 60), 2):
                pdf.set_x(15)
                pdf.cell(90, 3, safe_text(f"{i+1}. {sub_list[i]}"), ln=False)
                
                if i+1 < len(sub_list):
                    pdf.cell(90, 3, safe_text(f"{i+2}. {sub_list[i+1]}"), ln=True)
                else:
                    pdf.ln()
            
            if len(sub_list) > 60:
                pdf.set_font("Arial", 'I', 7)
                pdf.set_text_color(120, 120, 120)
                pdf.ln(2)
                pdf.cell(0, 3, f"... and {len(sub_list) - 60} additional subdomains not shown", ln=True)
        else:
            pdf.set_font("Arial", '', 9)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 5, "No subdomains discovered during reconnaissance", ln=True)
        
        # ============================================================
        # PAGE 10 - WEB ARCHIVES
        # ============================================================
        pdf.add_page()
        add_header_bar("08. WEB ARCHIVE HISTORY (WAYBACK MACHINE)")
        
        wb = data.get("wayback", {})
        
        if wb.get('available'):
            pdf.set_fill_color(240, 255, 240)
            pdf.rect(15, pdf.get_y(), 180, 10, 'F')
            pdf.set_xy(20, pdf.get_y() + 3)
            pdf.set_font("Arial", 'B', 10)
            pdf.set_text_color(0, 150, 100)
            pdf.cell(0, 4, "HISTORICAL ARCHIVES AVAILABLE", ln=True)
            pdf.ln(5)
            
            add_key_value("Total Snapshots", wb.get('total_snapshots', 'N/A'), True)
            add_key_value("Last Captured", wb.get('last_snapshot_formatted', wb.get('last_snapshot', 'N/A')))
            add_key_value("Archive Status", wb.get('status_code', 'N/A'))
            
            if wb.get('archive_url'):
                pdf.ln(3)
                add_divider()
                
                pdf.set_font("Arial", 'B', 9)
                pdf.set_text_color(100, 100, 100)
                pdf.cell(0, 5, "LATEST SNAPSHOT URL:", ln=True)
                pdf.set_font("Courier", '', 7)
                pdf.set_text_color(0, 100, 200)
                pdf.multi_cell(0, 4, safe_text(wb['archive_url']))
        else:
            pdf.set_fill_color(255, 250, 240)
            pdf.rect(15, pdf.get_y(), 180, 20, 'F')
            pdf.set_xy(20, pdf.get_y() + 7)
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(180, 140, 0)
            pdf.multi_cell(0, 5, safe_text(wb.get('message', 'No historical archives found for this domain')))
        
        # ============================================================
        # FINAL PAGE - REPORT SUMMARY
        # ============================================================
        pdf.add_page()
        
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 10, "REPORT SUMMARY & CONCLUSION", ln=True)
        pdf.ln(5)
        
        # Final risk assessment recap
        pdf.set_fill_color(245, 245, 250)
        pdf.rect(10, pdf.get_y(), 190, 35, 'F')
        
        pdf.set_xy(20, pdf.get_y() + 5)
        pdf.set_font("Arial", 'B', 11)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 6, "Final Security Assessment", ln=True)
        
        pdf.set_x(20)
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(170, 5, safe_text(
            f"Target '{data.get('target')}' has been assigned a risk score of {risk_score}/100 "
            f"with a threat level classification of {risk_level}. This assessment is based on "
            f"passive reconnaissance techniques and should be used as part of a comprehensive "
            f"security evaluation program."
        ))
        
        pdf.ln(8)
        add_divider()
        
        # Scan statistics
        pdf.set_font("Arial", 'B', 10)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 6, "RECONNAISSANCE STATISTICS", ln=True)
        pdf.ln(2)
        
        stats = [
            ("Total Issues Found", len(issues)),
            ("Security Recommendations", len(recommendations)),
            ("Subdomains Discovered", sub_count),
            ("DNS Records Retrieved", sum(1 for records in dns_data.values() if records)),
            ("Technologies Identified", sum(len(items) for items in tech_data.values()) if isinstance(tech_data, dict) else 0),
        ]
        
        for label, value in stats:
            add_key_value(label, value)
        
        # Footer notes
        pdf.ln(10)
        add_divider()
        
        pdf.set_font("Arial", 'I', 8)
        pdf.set_text_color(120, 120, 120)
        pdf.multi_cell(0, 4, 
            "DISCLAIMER: This report contains information gathered through passive reconnaissance "
            "techniques and is intended for authorized security testing and research purposes only. "
            "The accuracy of findings may vary based on target configuration and availability at the "
            "time of scanning. Always obtain proper authorization before conducting security assessments."
        )
        
        pdf.ln(5)
        pdf.set_xy(0, 280)
        pdf.set_font("Arial", '', 7)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 3, "Generated by CoreRecon Intelligence Platform v1.0", ln=True, align='C')
        pdf.cell(0, 3, f"Report ID: CR-{clean_domain.replace('.', '-').upper()}-{datetime.now().strftime('%Y%m%d')}", ln=True, align='C')
        
        # Bottom accent bar
        pdf.set_fill_color(0, 200, 255)
        pdf.rect(0, 294, 210, 3, 'F')
        
        # Generate PDF
        pdf_output = pdf.output(dest='S').encode('latin-1')
        headers = {
            'Content-Disposition': f'attachment; filename="CoreRecon_Intel_{clean_domain.replace(".", "_")}.pdf"'
        }
        return Response(content=pdf_output, headers=headers, media_type='application/pdf')

    except Exception as e:
        print(f"REPORT ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
           

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