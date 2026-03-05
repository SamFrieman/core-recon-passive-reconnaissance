"""
CoreRecon v2.0 — PDF Report Generator
Extracted from v1 main.py. Called by main.py as:
    from backend.report import generate_pdf_report
    pdf_bytes = generate_pdf_report(scan_data)
"""
from datetime import datetime
from fpdf import FPDF


def generate_pdf_report(data: dict) -> bytes:
    """
    Generate a full intelligence PDF report from scan data.
    Returns raw PDF bytes suitable for streaming to the client.
    """
    clean_domain = data.get("target", "unknown")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # --- Helper Functions ---

    def safe_text(text):
        return str(text).encode("latin-1", "replace").decode("latin-1")

    def add_header_bar(title, y_position=None):
        if y_position:
            pdf.set_y(y_position)
        pdf.set_fill_color(20, 30, 40)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_text_color(0, 200, 255)
        pdf.set_font("Arial", "B", 12)
        pdf.set_xy(15, pdf.get_y() + 2)
        pdf.cell(0, 6, title, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    def add_key_value(key, value, highlight=False):
        pdf.set_font("Arial", "B", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(50, 5, safe_text(key + ":"), ln=False)
        if highlight:
            pdf.set_text_color(0, 150, 200)
            pdf.set_font("Arial", "B", 9)
        else:
            pdf.set_text_color(60, 60, 60)
            pdf.set_font("Arial", "", 9)
        pdf.cell(0, 5, safe_text(str(value)), ln=True)
        pdf.set_text_color(0, 0, 0)

    def add_divider():
        pdf.set_draw_color(200, 200, 200)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)

    # ============================================================
    # COVER PAGE
    # ============================================================
    pdf.set_fill_color(15, 20, 30)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_fill_color(0, 200, 255)
    pdf.rect(0, 0, 210, 3, "F")

    pdf.set_xy(85, 60)
    pdf.set_fill_color(0, 150, 200)
    pdf.rect(85, 60, 40, 40, "F")
    pdf.set_font("Arial", "B", 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(85, 75)
    pdf.cell(40, 10, "CR", 0, 0, "C")

    pdf.set_xy(0, 120)
    pdf.set_font("Arial", "B", 36)
    pdf.set_text_color(0, 200, 255)
    pdf.cell(0, 15, "CORERECON", ln=True, align="C")

    pdf.set_font("Arial", "", 14)
    pdf.set_text_color(180, 180, 180)
    pdf.cell(0, 8, "INTELLIGENCE REPORT", ln=True, align="C")

    pdf.set_xy(40, 160)
    pdf.set_fill_color(30, 40, 50)
    pdf.rect(40, 160, 130, 30, "F")

    pdf.set_xy(40, 165)
    pdf.set_font("Arial", "B", 11)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(130, 6, "TARGET DOMAIN", 0, 1, "C")

    pdf.set_xy(40, 172)
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 200, 255)
    pdf.cell(130, 8, safe_text(data.get("target", clean_domain)), 0, 1, "C")

    pdf.set_xy(0, 210)
    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(140, 140, 140)
    pdf.cell(
        0,
        5,
        f"Report Generated: {data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}",
        ln=True,
        align="C",
    )
    pdf.cell(0, 5, "Classification: TLP:WHITE - For Authorized Use Only", ln=True, align="C")

    pdf.set_fill_color(0, 200, 255)
    pdf.rect(0, 294, 210, 3, "F")

    pdf.set_xy(0, 280)
    pdf.set_font("Arial", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "Powered by CoreRecon Intelligence Platform v2.0", ln=True, align="C")

    # ============================================================
    # PAGE 2 - EXECUTIVE SUMMARY
    # ============================================================
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)

    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(0, 150, 200)
    pdf.cell(0, 10, "EXECUTIVE SUMMARY", ln=True)
    pdf.set_draw_color(0, 200, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    risk_score = data.get("risk_score", 0)
    risk_level = data.get("risk_level", "UNKNOWN")

    pdf.set_fill_color(245, 245, 250)
    pdf.rect(10, pdf.get_y(), 190, 45, "F")

    pdf.set_xy(20, pdf.get_y() + 8)
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "OVERALL THREAT LEVEL", ln=True)

    pdf.set_x(20)
    pdf.set_font("Arial", "B", 32)

    if risk_level in ["MINIMAL", "LOW"]:
        pdf.set_text_color(0, 180, 100)
    elif risk_level == "MEDIUM":
        pdf.set_text_color(255, 160, 0)
    else:
        pdf.set_text_color(255, 60, 60)

    pdf.cell(50, 12, f"{risk_score}/100", ln=False)
    pdf.set_font("Arial", "B", 24)
    pdf.cell(0, 12, risk_level, ln=True)

    pdf.set_x(20)
    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(0, 5, safe_text(data.get("risk_status", "Assessment complete")))

    pdf.ln(5)
    add_divider()

    issues = data.get("risk_issues", [])
    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(255, 60, 60)
    pdf.cell(0, 7, f"CRITICAL FINDINGS ({len(issues)})", ln=True)

    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(60, 60, 60)

    if issues:
        for i, issue in enumerate(issues, 1):
            pdf.set_fill_color(255, 245, 245)
            pdf.rect(15, pdf.get_y(), 180, 8, "F")
            pdf.set_xy(18, pdf.get_y() + 2)
            pdf.cell(10, 4, f"{i}.", ln=False)
            pdf.multi_cell(165, 4, safe_text(issue))
    else:
        pdf.set_fill_color(240, 255, 240)
        pdf.rect(15, pdf.get_y(), 180, 8, "F")
        pdf.set_xy(18, pdf.get_y() + 2)
        pdf.set_text_color(0, 150, 100)
        pdf.cell(0, 4, "No critical vulnerabilities detected", ln=True)

    pdf.ln(5)
    add_divider()

    recommendations = data.get("recommendations", [])
    if recommendations:
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 7, f"SECURITY RECOMMENDATIONS ({len(recommendations)})", ln=True)
        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(60, 60, 60)
        for i, rec in enumerate(recommendations[:5], 1):
            pdf.set_fill_color(240, 250, 255)
            pdf.rect(15, pdf.get_y(), 180, 8, "F")
            pdf.set_xy(18, pdf.get_y() + 2)
            pdf.cell(10, 4, f"{i}.", ln=False)
            pdf.multi_cell(165, 4, safe_text(rec))

    # ============================================================
    # PAGE 3 - INFRASTRUCTURE & NETWORK
    # ============================================================
    pdf.add_page()
    add_header_bar("01. INFRASTRUCTURE & NETWORK INTELLIGENCE")

    infra = data.get("infrastructure", {})
    status = infra.get("status", "UNKNOWN")
    if status == "ONLINE":
        pdf.set_fill_color(0, 180, 100)
    else:
        pdf.set_fill_color(255, 80, 80)

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(40, 7, f"STATUS: {status}", 0, 1, "C", True)
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)

    add_key_value("Primary IP Address", infra.get("ip", "N/A"), True)
    add_key_value("Reverse DNS", infra.get("reverse_dns", "N/A"))

    if infra.get("asn"):
        add_key_value("ASN Number", infra["asn"].get("number", "N/A"))
        add_key_value("ASN Organization", infra["asn"].get("organization", "N/A"))

    add_key_value("ISP Provider", infra.get("provider", "N/A"))
    add_key_value("Organization", infra.get("organization", "N/A"))

    pdf.ln(3)
    add_divider()

    loc = infra.get("location", {})
    if loc:
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 6, "GEOGRAPHIC LOCATION", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)
        add_key_value("City", loc.get("city", "Unknown"))
        add_key_value("Region", loc.get("region", "Unknown"))
        add_key_value("Country", loc.get("country", "Unknown"))
        add_key_value("Coordinates", loc.get("coordinates", "N/A"))

    # ============================================================
    # PAGE 4 - SYSTEM FINGERPRINT
    # ============================================================
    pdf.add_page()
    add_header_bar("02. SYSTEM FINGERPRINT & SECURITY HEADERS")

    fing = data.get("fingerprint", {})
    add_key_value("Web Server", fing.get("server", "Hidden/Unknown"))
    add_key_value("Protocol", fing.get("protocol", "N/A"), True)
    add_key_value("HTTP Status", fing.get("status_code", "N/A"))
    add_key_value("Powered By", fing.get("powered_by", "Not Disclosed"))
    add_key_value("Cookies Set", fing.get("cookies", 0))

    pdf.ln(3)
    add_divider()

    pdf.set_font("Arial", "B", 10)
    pdf.set_text_color(0, 150, 200)
    pdf.cell(0, 6, "SECURITY HEADER ANALYSIS", ln=True)
    pdf.ln(2)

    pdf.set_fill_color(240, 240, 245)
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(120, 6, "Security Header", 1, 0, "L", True)
    pdf.cell(60, 6, "Status", 1, 1, "C", True)

    pdf.set_font("Arial", "", 8)
    for head, val in fing.get("security", {}).items():
        pdf.cell(120, 5, safe_text(head.replace("-", " ").upper()), 1, 0, "L")
        if val == "MISSING":
            pdf.set_fill_color(255, 240, 240)
            pdf.set_text_color(200, 50, 50)
        else:
            pdf.set_fill_color(240, 255, 240)
            pdf.set_text_color(0, 150, 100)
        pdf.cell(60, 5, "MISSING" if val == "MISSING" else "CONFIGURED", 1, 1, "C", True)
        pdf.set_text_color(60, 60, 60)

    # ============================================================
    # PAGE 5 - SSL CERTIFICATE
    # ============================================================
    pdf.add_page()
    add_header_bar("03. SSL/TLS CERTIFICATE INFORMATION")

    ssl_data = data.get("ssl_certificate", {})

    if "error" not in ssl_data:
        days_remaining = ssl_data.get("days_remaining", 0)
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
        pdf.set_font("Arial", "B", 10)
        pdf.cell(60, 7, f"CERTIFICATE: {status_text}", 0, 0, "C", True)
        pdf.set_fill_color(240, 240, 245)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(60, 7, f"{days_remaining} Days Remaining", 0, 1, "C", True)
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)

        add_key_value("TLS Version", ssl_data.get("tls_version", "N/A"), True)
        add_key_value("Signature Algorithm", ssl_data.get("signature_algorithm", "N/A"))
        add_key_value("Serial Number", ssl_data.get("serial_number", "N/A"))

        pdf.ln(2)
        add_divider()

        pdf.set_font("Arial", "B", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, "ISSUER:", ln=True)
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, safe_text(ssl_data.get("issuer", "N/A")))

        pdf.ln(2)
        pdf.set_font("Arial", "B", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, "SUBJECT:", ln=True)
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, safe_text(ssl_data.get("subject", "N/A")))

        pdf.ln(2)
        add_divider()

        add_key_value("Valid From", ssl_data.get("valid_from", "N/A"))
        add_key_value("Valid Until", ssl_data.get("valid_until", "N/A"))

        sans = ssl_data.get("subject_alternative_names", [])
        if sans:
            pdf.ln(2)
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 5, f"SUBJECT ALTERNATIVE NAMES ({len(sans)})", ln=True)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(60, 60, 60)
            for san in sans[:15]:
                pdf.cell(0, 3, f"  > {safe_text(san)}", ln=True)
    else:
        pdf.set_fill_color(255, 240, 240)
        pdf.rect(15, pdf.get_y(), 180, 20, "F")
        pdf.set_xy(20, pdf.get_y() + 7)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(200, 50, 50)
        pdf.cell(0, 6, "No SSL/TLS certificate detected for this target", ln=True)

    # ============================================================
    # PAGE 6 - DNS RECORDS
    # ============================================================
    pdf.add_page()
    add_header_bar("04. DNS RECORDS & CONFIGURATION")

    dns_data = data.get("dns", {})
    for r_type, records in dns_data.items():
        if not records or not isinstance(records, list) or len(records) == 0:
            continue
        if "Query failed" in records[0] or "timeout" in records[0]:
            continue

        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 6, f"{r_type} RECORDS ({len(records)})", ln=True)
        pdf.ln(1)

        pdf.set_fill_color(245, 245, 250)
        pdf.rect(15, pdf.get_y(), 180, 5 + (len(records[:10]) * 4), "F")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(60, 60, 60)

        for record in records[:10]:
            pdf.set_x(18)
            pdf.cell(0, 4, safe_text(f"> {record}"), ln=True)

        if len(records) > 10:
            pdf.set_x(18)
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 4, f"... and {len(records) - 10} more records", ln=True)

        pdf.ln(4)

    # ============================================================
    # PAGE 7 - WHOIS DATA
    # ============================================================
    pdf.add_page()
    add_header_bar("05. WHOIS & DOMAIN REGISTRATION")

    whois_data = data.get("whois", {})
    if not whois_data.get("error"):
        add_key_value("Registrar", whois_data.get("registrar", "N/A"), True)
        add_key_value("Organization", whois_data.get("organization", "Private/Redacted"))
        add_key_value("Registrant Country", whois_data.get("registrant_country", "Private/Redacted"))
        add_key_value("DNSSEC", whois_data.get("dnssec", "Unsigned"))

        pdf.ln(3)
        add_divider()

        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 6, "IMPORTANT DATES", ln=True)
        pdf.ln(2)

        add_key_value("Created", whois_data.get("creation_date", "Unknown"))
        add_key_value("Last Updated", whois_data.get("updated_date", "Unknown"))
        add_key_value("Expires", whois_data.get("expiration_date", "Unknown"))

        ns_list = whois_data.get("name_servers", [])
        if ns_list:
            pdf.ln(3)
            add_divider()
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 6, f"NAME SERVERS ({len(ns_list)})", ln=True)
            pdf.ln(2)
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(60, 60, 60)
            for ns in ns_list[:8]:
                pdf.cell(0, 4, f"  > {safe_text(ns)}", ln=True)
    else:
        pdf.set_fill_color(255, 250, 240)
        pdf.rect(15, pdf.get_y(), 180, 15, "F")
        pdf.set_xy(20, pdf.get_y() + 5)
        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(180, 140, 0)
        pdf.multi_cell(0, 5, safe_text(whois_data.get("note", "WHOIS data unavailable or privacy protected")))

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

            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(0, 150, 200)
            pdf.cell(0, 6, f"{safe_text(str(category).upper())} ({len(items)})", ln=True)
            pdf.ln(1)
            pdf.set_fill_color(245, 245, 250)

            if isinstance(items, list):
                for item in items[:15]:
                    pdf.rect(15, pdf.get_y(), 180, 6, "F")
                    if isinstance(item, dict):
                        name = item.get("name", "Unknown")
                        ver = item.get("version", "Undetected")
                        pdf.set_xy(18, pdf.get_y() + 1.5)
                        pdf.set_font("Arial", "B", 8)
                        pdf.set_text_color(60, 60, 60)
                        pdf.cell(100, 3, safe_text(name), ln=False)
                        pdf.set_font("Courier", "", 7)
                        if ver != "Undetected":
                            pdf.set_text_color(0, 150, 200)
                        else:
                            pdf.set_text_color(150, 150, 150)
                        pdf.cell(0, 3, safe_text(f"v{ver}"), ln=True)
                    else:
                        pdf.set_xy(18, pdf.get_y() + 1.5)
                        pdf.set_font("Arial", "", 8)
                        pdf.set_text_color(60, 60, 60)
                        pdf.cell(0, 3, safe_text(str(item)), ln=True)

            pdf.ln(3)
    else:
        pdf.set_fill_color(245, 245, 250)
        pdf.rect(15, pdf.get_y(), 180, 15, "F")
        pdf.set_xy(20, pdf.get_y() + 5)
        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 5, "No technology signatures identified", ln=True)

    # ============================================================
    # PAGE 9 - SUBDOMAINS
    # ============================================================
    pdf.add_page()
    add_header_bar("07. SUBDOMAIN DISCOVERY & ENUMERATION")

    subs = data.get("subdomains", {})
    sub_count = subs.get("count", 0)

    pdf.set_font("Arial", "B", 14)
    pdf.set_text_color(0, 150, 200)
    pdf.cell(0, 8, f"{sub_count} SUBDOMAINS DISCOVERED", ln=True)
    pdf.ln(3)

    if subs.get("sources"):
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 4, f"Sources: {', '.join(subs['sources'])}", ln=True)
        pdf.ln(2)

    add_divider()

    sub_list = subs.get("subdomains", [])
    if sub_list:
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(60, 60, 60)
        for i in range(0, min(len(sub_list), 60), 2):
            pdf.set_x(15)
            pdf.cell(90, 3, safe_text(f"{i+1}. {sub_list[i]}"), ln=False)
            if i + 1 < len(sub_list):
                pdf.cell(90, 3, safe_text(f"{i+2}. {sub_list[i+1]}"), ln=True)
            else:
                pdf.ln()
        if len(sub_list) > 60:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(120, 120, 120)
            pdf.ln(2)
            pdf.cell(0, 3, f"... and {len(sub_list) - 60} additional subdomains not shown", ln=True)
    else:
        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 5, "No subdomains discovered during reconnaissance", ln=True)

    # ============================================================
    # PAGE 10 - WEB ARCHIVES
    # ============================================================
    pdf.add_page()
    add_header_bar("08. WEB ARCHIVE HISTORY (WAYBACK MACHINE)")

    wb = data.get("wayback", {})
    if wb.get("available"):
        pdf.set_fill_color(240, 255, 240)
        pdf.rect(15, pdf.get_y(), 180, 10, "F")
        pdf.set_xy(20, pdf.get_y() + 3)
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 150, 100)
        pdf.cell(0, 4, "HISTORICAL ARCHIVES AVAILABLE", ln=True)
        pdf.ln(5)

        add_key_value("Total Snapshots", wb.get("total_snapshots", "N/A"), True)
        add_key_value("Last Captured", wb.get("last_snapshot_formatted", wb.get("last_snapshot", "N/A")))
        add_key_value("Archive Status", wb.get("status_code", "N/A"))

        if wb.get("archive_url"):
            pdf.ln(3)
            add_divider()
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, "LATEST SNAPSHOT URL:", ln=True)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(0, 100, 200)
            pdf.multi_cell(0, 4, safe_text(wb["archive_url"]))
    else:
        pdf.set_fill_color(255, 250, 240)
        pdf.rect(15, pdf.get_y(), 180, 20, "F")
        pdf.set_xy(20, pdf.get_y() + 7)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(180, 140, 0)
        pdf.multi_cell(0, 5, safe_text(wb.get("message", "No historical archives found for this domain")))

    # ============================================================
    # FINAL PAGE - REPORT SUMMARY
    # ============================================================
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 150, 200)
    pdf.cell(0, 10, "REPORT SUMMARY & CONCLUSION", ln=True)
    pdf.ln(5)

    pdf.set_fill_color(245, 245, 250)
    pdf.rect(10, pdf.get_y(), 190, 35, "F")

    pdf.set_xy(20, pdf.get_y() + 5)
    pdf.set_font("Arial", "B", 11)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, "Final Security Assessment", ln=True)

    pdf.set_x(20)
    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        170,
        5,
        safe_text(
            f"Target '{data.get('target')}' has been assigned a risk score of {risk_score}/100 "
            f"with a threat level classification of {risk_level}. This assessment is based on "
            f"passive reconnaissance techniques and should be used as part of a comprehensive "
            f"security evaluation program."
        ),
    )

    pdf.ln(8)
    add_divider()

    pdf.set_font("Arial", "B", 10)
    pdf.set_text_color(0, 150, 200)
    pdf.cell(0, 6, "RECONNAISSANCE STATISTICS", ln=True)
    pdf.ln(2)

    stats = [
        ("Total Issues Found", len(issues)),
        ("Security Recommendations", len(recommendations)),
        ("Subdomains Discovered", sub_count),
        ("DNS Records Retrieved", sum(1 for records in dns_data.values() if records)),
        (
            "Technologies Identified",
            sum(len(items) for items in tech_data.values()) if isinstance(tech_data, dict) else 0,
        ),
    ]
    for label, value in stats:
        add_key_value(label, value)

    pdf.ln(10)
    add_divider()

    pdf.set_font("Arial", "I", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(
        0,
        4,
        "DISCLAIMER: This report contains information gathered through passive reconnaissance "
        "techniques and is intended for authorized security testing and research purposes only. "
        "The accuracy of findings may vary based on target configuration and availability at the "
        "time of scanning. Always obtain proper authorization before conducting security assessments.",
    )

    pdf.ln(5)
    pdf.set_xy(0, 280)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 3, "Generated by CoreRecon Intelligence Platform v2.0", ln=True, align="C")
    pdf.cell(
        0,
        3,
        f"Report ID: CR-{clean_domain.replace('.', '-').upper()}-{datetime.now().strftime('%Y%m%d')}",
        ln=True,
        align="C",
    )

    pdf.set_fill_color(0, 200, 255)
    pdf.rect(0, 294, 210, 3, "F")

    return pdf.output(dest="S").encode("latin-1")
