"""
CoreRecon DNS Intelligence Module
Retrieves all DNS record types (preserving v1 output) plus:
- SPF record analysis and policy scoring
- DMARC policy parsing
- DNSSEC presence detection
- MX provider classification
- Nameserver provider classification
"""
import re
from typing import Dict, List, Any

import dns.resolver
import dns.exception

from backend.core.logger import get_logger

log = get_logger("corerecon.dns")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

# ---------------------------------------------------------------------------
# MX Provider fingerprinting — passive, based on MX hostname patterns
# ---------------------------------------------------------------------------

MX_PROVIDER_PATTERNS = [
    (re.compile(r"google\.com|gmail\.com|googlemail\.com", re.I), "Google Workspace"),
    (re.compile(r"outlook\.com|hotmail\.com|microsoft\.com|protection\.outlook", re.I), "Microsoft 365"),
    (re.compile(r"proofpoint\.com", re.I), "Proofpoint"),
    (re.compile(r"mimecast\.com", re.I), "Mimecast"),
    (re.compile(r"mailgun\.org", re.I), "Mailgun"),
    (re.compile(r"sendgrid\.net", re.I), "SendGrid"),
    (re.compile(r"amazonses\.com", re.I), "Amazon SES"),
    (re.compile(r"barracuda", re.I), "Barracuda"),
    (re.compile(r"pphosted\.com", re.I), "Proofpoint"),
    (re.compile(r"zoho\.com", re.I), "Zoho Mail"),
    (re.compile(r"fastmail", re.I), "Fastmail"),
    (re.compile(r"messagelabs|symantec", re.I), "Symantec Email Security"),
    (re.compile(r"spamhero\.com", re.I), "SpamHero"),
]

NS_PROVIDER_PATTERNS = [
    (re.compile(r"cloudflare\.com", re.I), "Cloudflare"),
    (re.compile(r"awsdns", re.I), "Amazon Route 53"),
    (re.compile(r"azure-dns\.com|azure-dns\.net|azure-dns\.org|azure-dns\.info", re.I), "Azure DNS"),
    (re.compile(r"googledns\.com|googledomains\.com|google\.com", re.I), "Google Cloud DNS"),
    (re.compile(r"domaincontrol\.com", re.I), "GoDaddy"),
    (re.compile(r"registrar-servers\.com|namecheap", re.I), "Namecheap"),
    (re.compile(r"dnsimple\.com", re.I), "DNSimple"),
    (re.compile(r"nsone\.net", re.I), "NS1"),
    (re.compile(r"ultradns\.net|ultradns\.com|ultradns\.org|ultradns\.biz", re.I), "UltraDNS"),
    (re.compile(r"dynect\.net", re.I), "Dyn DNS"),
]


def _classify_mx_provider(mx_records: List[str]) -> str:
    """Identify the mail service provider from MX records."""
    for record in mx_records:
        for pattern, provider in MX_PROVIDER_PATTERNS:
            if pattern.search(record):
                return provider
    return "Unknown / Self-hosted"


def _classify_ns_provider(ns_records: List[str]) -> str:
    """Identify the DNS provider from NS records."""
    for record in ns_records:
        for pattern, provider in NS_PROVIDER_PATTERNS:
            if pattern.search(record):
                return provider
    return "Unknown / Self-managed"


def _analyze_spf(txt_records: List[str]) -> Dict[str, Any]:
    """
    Parse SPF record from TXT records.
    Returns structured SPF analysis.
    """
    spf_record = None
    for record in txt_records:
        if record.strip().startswith("v=spf1"):
            spf_record = record.strip()
            break

    if not spf_record:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "policy_strength": "NONE",
            "all_qualifier": None,
            "risk": "HIGH",
            "note": "No SPF record found. Domain is vulnerable to email spoofing.",
        }

    # Determine the 'all' qualifier
    all_match = re.search(r"([+\-~?])all", spf_record)
    all_qualifier = all_match.group(1) if all_match else None

    qualifier_map = {
        "+": ("PASS_ALL", "CRITICAL", "SPF allows all senders — effectively useless protection"),
        "?": ("NEUTRAL", "HIGH", "SPF neutral policy provides minimal protection"),
        "~": ("SOFT_FAIL", "MEDIUM", "SPF soft fail — legitimate emails may pass, attackers flagged but not blocked"),
        "-": ("HARD_FAIL", "LOW", "SPF hard fail — strict policy, unauthenticated mail rejected"),
        None: ("NONE", "MEDIUM", "SPF record has no 'all' mechanism"),
    }

    policy, risk, note = qualifier_map.get(all_qualifier, ("UNKNOWN", "MEDIUM", "Unable to parse SPF policy"))

    return {
        "present": True,
        "record": spf_record,
        "policy": policy,
        "policy_strength": policy,
        "all_qualifier": all_qualifier,
        "risk": risk,
        "note": note,
    }


def _get_dmarc(domain: str) -> Dict[str, Any]:
    """
    Query _dmarc.{domain} for DMARC TXT record and parse its policy.
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=8)
        records = []
        for rdata in answers:
            for string in rdata.strings:
                try:
                    records.append(string.decode("utf-8"))
                except Exception:
                    records.append(str(string))

        dmarc_record = None
        for r in records:
            if r.startswith("v=DMARC1"):
                dmarc_record = r
                break

        if not dmarc_record:
            return {"present": False, "record": None, "policy": None, "risk": "HIGH",
                    "note": "No valid DMARC record found."}

        # Parse p= tag
        p_match = re.search(r"\bp=(\w+)", dmarc_record)
        policy = p_match.group(1).lower() if p_match else "none"

        # Parse pct= tag
        pct_match = re.search(r"\bpct=(\d+)", dmarc_record)
        pct = int(pct_match.group(1)) if pct_match else 100

        # Parse sp= (subdomain policy)
        sp_match = re.search(r"\bsp=(\w+)", dmarc_record)
        sp = sp_match.group(1).lower() if sp_match else policy

        policy_risk = {
            "none": ("MEDIUM", "DMARC policy is 'none' — monitoring only, no enforcement"),
            "quarantine": ("LOW", "DMARC quarantine policy — suspicious mail sent to spam"),
            "reject": ("MINIMAL", "DMARC reject policy — strict enforcement"),
        }.get(policy, ("HIGH", "Unrecognized DMARC policy"))

        risk, note = policy_risk

        return {
            "present": True,
            "record": dmarc_record,
            "policy": policy,
            "subdomain_policy": sp,
            "percentage": pct,
            "risk": risk,
            "note": note,
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "present": False,
            "record": None,
            "policy": None,
            "risk": "HIGH",
            "note": "No DMARC record found. Domain is vulnerable to email spoofing.",
        }
    except Exception as e:
        log.warning("DMARC lookup failed", extra={"domain": domain, "error": str(e)})
        return {"present": False, "error": str(e), "risk": "UNKNOWN"}


def _check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Passive DNSSEC check: look for DNSKEY records.
    If DNSKEY records exist, the zone is DNSSEC-signed.
    """
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=8)
        return {"enabled": True, "note": "DNSKEY records found — zone appears DNSSEC-signed"}
    except dns.resolver.NoAnswer:
        return {"enabled": False, "note": "No DNSKEY records found — DNSSEC not detected"}
    except dns.resolver.NXDOMAIN:
        return {"enabled": False, "note": "Domain does not exist"}
    except Exception as e:
        log.warning("DNSSEC check failed", extra={"domain": domain, "error": str(e)})
        return {"enabled": False, "error": str(e), "note": "DNSSEC check inconclusive"}


def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieve all DNS records for the domain.

    Preserves v1 response structure exactly:
      dns.A, dns.AAAA, dns.MX, dns.NS, dns.TXT, dns.SOA, dns.CNAME

    Adds v2 enrichments:
      dns.spf, dns.dmarc, dns.dnssec, dns.mx_provider, dns.ns_provider
    """
    dns_data: Dict[str, Any] = {}
    raw_txt: List[str] = []

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=8)
            records = []
            for rdata in answers:
                if record_type == "TXT":
                    # TXT records can be multi-string — join them
                    try:
                        decoded = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    except Exception:
                        decoded = str(rdata)
                    records.append(decoded)
                    raw_txt.append(decoded)
                else:
                    records.append(str(rdata))
            dns_data[record_type] = records

        except dns.resolver.NoAnswer:
            dns_data[record_type] = []
        except dns.resolver.NXDOMAIN:
            dns_data[record_type] = ["Domain does not exist"]
            break
        except dns.exception.Timeout:
            dns_data[record_type] = ["Query timed out"]
        except Exception:
            dns_data[record_type] = ["Query failed"]

    # --- v2 intelligence enrichments ---
    mx_records = dns_data.get("MX", [])
    ns_records = dns_data.get("NS", [])

    dns_data["spf"] = _analyze_spf(raw_txt)
    dns_data["dmarc"] = _get_dmarc(domain)
    dns_data["dnssec"] = _check_dnssec(domain)
    dns_data["mx_provider"] = _classify_mx_provider(mx_records)
    dns_data["ns_provider"] = _classify_ns_provider(ns_records)

    log.info(
        "DNS records gathered",
        extra={
            "domain": domain,
            "spf_present": dns_data["spf"]["present"],
            "dmarc_present": dns_data["dmarc"]["present"],
            "dnssec_enabled": dns_data["dnssec"]["enabled"],
        },
    )
    return dns_data
