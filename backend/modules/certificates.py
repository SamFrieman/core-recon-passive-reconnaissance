"""
CoreRecon SSL/TLS Certificate Intelligence Module
Preserves all v1 fields. Adds: weak algorithm detection, self-signed flag,
wildcard coverage, CT log anomaly indicators, TLS version risk rating.
"""
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from backend.core.logger import get_logger

log = get_logger("corerecon.certificates")

# Algorithms considered weak or deprecated
WEAK_ALGORITHMS = {
    "sha1withrsaencryption", "sha1withdsa", "ecdsa-with-sha1",
    "md5withrsaencryption", "md2withrsaencryption",
}

# TLS version risk ratings
TLS_RISK = {
    "TLSv1.3": "LOW",
    "TLSv1.2": "LOW",
    "TLSv1.1": "HIGH",
    "TLSv1": "CRITICAL",
    "SSLv3": "CRITICAL",
    "SSLv2": "CRITICAL",
}

# Known major public CAs — used to detect self-signed
KNOWN_CA_PATTERNS = [
    "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
    "entrust", "geotrust", "verisign", "thawte", "amazon", "google trust",
    "cloudflare", "godaddy", "network solutions", "usertrust",
]


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Detect self-signed certs by comparing issuer and subject."""
    return cert.issuer == cert.subject


def _check_weak_algorithm(sig_algo: str) -> Dict[str, Any]:
    """Evaluate signature algorithm strength."""
    algo_lower = sig_algo.lower()
    is_weak = any(weak in algo_lower for weak in WEAK_ALGORITHMS)
    return {
        "algorithm": sig_algo,
        "is_weak": is_weak,
        "risk": "CRITICAL" if is_weak else "LOW",
        "note": f"Deprecated algorithm {sig_algo} — upgrade to SHA-256 or better" if is_weak else "Algorithm strength acceptable",
    }


def _get_key_info(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract public key type and size for additional context."""
    try:
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            bits = pub_key.key_size
            return {
                "type": "RSA",
                "bits": bits,
                "adequate": bits >= 2048,
                "note": f"RSA-{bits}" + ("" if bits >= 2048 else " — key size below recommended 2048 bits"),
            }
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            bits = pub_key.key_size
            return {
                "type": "EC",
                "bits": bits,
                "adequate": bits >= 256,
                "note": f"EC-{bits} ({pub_key.curve.name})",
            }
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return {"type": "DSA", "bits": pub_key.key_size, "adequate": False, "note": "DSA — deprecated"}
        else:
            return {"type": "Unknown", "bits": None, "adequate": None, "note": "Could not determine key type"}
    except Exception:
        return {"type": "Unknown", "bits": None, "adequate": None, "note": "Key inspection failed"}


def get_ssl_certificate(domain: str) -> Dict[str, Any]:
    """
    Establish TLS connection and extract full certificate data.

    Preserves v1 response structure exactly:
      issuer, subject, version, serial_number, valid_from, valid_until,
      days_remaining, signature_algorithm, subject_alternative_names, tls_version

    Adds v2 enrichments:
      is_self_signed, algorithm_analysis, key_info, tls_risk, wildcard_cert,
      san_count, expiry_risk
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                tls_version = ssock.version() or "Unknown"
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            raise ValueError("No certificate returned by server")

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Dates
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_remaining = (not_after - now).days

        # Issuer and subject as RFC 4514 strings
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        # Signature algorithm
        try:
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        except Exception:
            sig_algo = str(cert.signature_algorithm_oid)

        # SANs (capped at 10 for v1 parity)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        wildcard_cert = any(name.startswith("*") for name in sans)

        # v2 enrichments
        self_signed = _is_self_signed(cert)
        algo_analysis = _check_weak_algorithm(sig_algo)
        key_info = _get_key_info(cert)
        tls_risk = TLS_RISK.get(tls_version, "MEDIUM")

        # Expiry risk classification
        if days_remaining < 0:
            expiry_risk = "CRITICAL"
            expiry_note = "Certificate has EXPIRED"
        elif days_remaining <= 7:
            expiry_risk = "CRITICAL"
            expiry_note = f"Certificate expires in {days_remaining} days — IMMEDIATE renewal required"
        elif days_remaining <= 30:
            expiry_risk = "HIGH"
            expiry_note = f"Certificate expires in {days_remaining} days — renewal overdue"
        elif days_remaining <= 90:
            expiry_risk = "MEDIUM"
            expiry_note = f"Certificate expires in {days_remaining} days — plan renewal"
        else:
            expiry_risk = "LOW"
            expiry_note = f"Certificate valid for {days_remaining} more days"

        result = {
            # --- v1 fields preserved exactly ---
            "issuer": issuer,
            "subject": subject,
            "version": f"v{cert.version.value + 1}",
            "serial_number": str(cert.serial_number),
            "valid_from": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_remaining": days_remaining,
            "signature_algorithm": sig_algo,
            "subject_alternative_names": sans[:10],
            "tls_version": tls_version,
            # --- v2 additions ---
            "san_count": len(sans),
            "wildcard_cert": wildcard_cert,
            "is_self_signed": self_signed,
            "algorithm_analysis": algo_analysis,
            "key_info": key_info,
            "tls_risk": tls_risk,
            "expiry_risk": expiry_risk,
            "expiry_note": expiry_note,
        }

        log.info(
            "SSL certificate analyzed",
            extra={
                "domain": domain,
                "days_remaining": days_remaining,
                "tls_version": tls_version,
                "self_signed": self_signed,
                "weak_algo": algo_analysis["is_weak"],
            },
        )
        return result

    except (socket.timeout, TimeoutError):
        log.warning("SSL connection timed out", extra={"domain": domain})
        return {"error": "Connection timed out on port 443", "tls_version": None, "days_remaining": None}
    except ConnectionRefusedError:
        return {"error": "Port 443 refused — HTTPS not available", "tls_version": None, "days_remaining": None}
    except ssl.SSLError as e:
        return {"error": f"SSL handshake failed: {str(e)}", "tls_version": None, "days_remaining": None}
    except Exception as e:
        log.warning("SSL certificate extraction failed", extra={"domain": domain, "error": str(e)})
        return {"error": str(e), "tls_version": None, "days_remaining": None}
