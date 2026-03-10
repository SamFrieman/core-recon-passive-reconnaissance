"""
CoreRecon v2.3 - PDF Report Generator

Fixes vs v2.3 original:
  - st() now handles em dash, en dash, smart quotes (were rendering as ?)
  - sub_count uses total_found (was using non-existent 'count' key — showed 0)
  - Infrastructure badge uses infra.get("online") (was checking non-existent 'status' key)
  - Subdomain list switched to 2-column layout with 42-char labels (was 3-col/26-char, truncated mid-word)
  - Stats section subdomain count fixed to match corrected sub_count
"""
from datetime import datetime
from fpdf import FPDF


def _as_dict(value, fallback=None) -> dict:
    if fallback is None:
        fallback = {}
    return value if isinstance(value, dict) else fallback


def _as_list(value, fallback=None) -> list:
    if fallback is None:
        fallback = []
    return value if isinstance(value, list) else fallback


def generate_pdf_report(data: dict) -> bytes:
    """Generate a compact, flow-based intelligence PDF. Returns raw bytes."""
    if not isinstance(data, dict):
        data = {}

    target = data.get("target", "unknown")
    risk_score = data.get("risk_score", 0)
    risk_level = data.get("risk_level", "UNKNOWN")
    issues = _as_list(data.get("risk_issues", []))
    recommendations = _as_list(data.get("recommendations", []))
    timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    C_ACCENT  = (0,  190, 255)
    C_DARK    = (15,  22,  35)
    C_LABEL   = (100,100,100)
    C_VALUE   = (45,  45,  45)
    C_SECTION = (0,  140, 200)
    C_SUCCESS = (0,  170,  90)
    C_WARN    = (230,140,  0)
    C_DANGER  = (220, 50,  50)
    C_ROWEVEN = (248,249,252)
    C_ROWODD  = (255,255,255)

    if risk_level in ("MINIMAL", "LOW"):
        C_RISK = C_SUCCESS
    elif risk_level == "MEDIUM":
        C_RISK = C_WARN
    else:
        C_RISK = C_DANGER

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)

    def st(text):
        """
        Convert text to latin-1 safe string.
        Replaces common unicode characters that have no latin-1 equivalent
        rather than letting encode(..., 'replace') silently drop them as '?'.
        """
        s = str(text)
        s = s.replace('\u2014', ' - ')    # em dash —
        s = s.replace('\u2013', ' - ')    # en dash –
        s = s.replace('\u2019', "'")      # right single quotation mark '
        s = s.replace('\u2018', "'")      # left single quotation mark '
        s = s.replace('\u201c', '"')      # left double quotation mark "
        s = s.replace('\u201d', '"')      # right double quotation mark "
        s = s.replace('\u2022', '*')      # bullet •
        s = s.replace('\u00b7', '.')      # middle dot
        s = s.replace('\u2026', '...')    # ellipsis …
        return s.encode("latin-1", "replace").decode("latin-1")

    def need_space(mm=40):
        if pdf.get_y() > (297 - 18 - mm):
            pdf.add_page()

    def section(title, sub=None):
        need_space(30)
        y = pdf.get_y()
        pdf.set_fill_color(*C_ACCENT)
        pdf.rect(10, y, 3, 8, "F")
        pdf.set_xy(15, y)
        pdf.set_font("Arial", "B", 11)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(0, 8, st(title), ln=True)
        if sub:
            pdf.set_x(15)
            pdf.set_font("Arial", "", 7)
            pdf.set_text_color(*C_LABEL)
            pdf.cell(0, 4, st(sub), ln=True)
        pdf.set_draw_color(220, 228, 236)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)
        pdf.set_text_color(*C_VALUE)

    def kv_grid(pairs, col_w=90):
        items = [p for p in pairs if str(p[1]) not in ("", "N/A", "Unknown", "None")]
        if not items:
            return
        row = 0
        for idx in range(0, len(items), 2):
            bg = C_ROWEVEN if row % 2 == 0 else C_ROWODD
            pdf.set_fill_color(*bg)
            y = pdf.get_y()
            pdf.set_x(10)
            pdf.rect(10, y, 190, 6, "F")
            for col, (key, val) in enumerate(items[idx:idx+2]):
                pdf.set_xy(10 + col * col_w, y + 1)
                pdf.set_font("Arial", "B", 7.5)
                pdf.set_text_color(*C_LABEL)
                pdf.cell(28, 4, st(key + ":"), ln=False)
                pdf.set_font("Arial", "", 7.5)
                pdf.set_text_color(*C_VALUE)
                pdf.cell(col_w - 28, 4, st(str(val)[:60]), ln=False)
            pdf.set_x(10)
            pdf.ln(6)
            row += 1

    def kv_full(key, val, color=None):
        if str(val) in ("", "N/A", "None"):
            return
        pdf.set_x(10)
        pdf.set_font("Arial", "B", 7.5)
        pdf.set_text_color(*C_LABEL)
        pdf.cell(35, 5, st(key + ":"), ln=False)
        pdf.set_x(45)
        pdf.set_font("Arial", "", 7.5)
        pdf.set_text_color(*(color if color else C_VALUE))
        pdf.multi_cell(150, 5, st(str(val)))
        pdf.set_text_color(*C_VALUE)

    def badge(text, r, g, b):
        w = len(text) * 1.8 + 6
        x, y = pdf.get_x(), pdf.get_y()
        pdf.set_fill_color(r, g, b)
        pdf.rect(x, y, w, 5, "F")
        pdf.set_xy(x, y)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 6)
        pdf.cell(w, 5, st(text), align="C")
        pdf.set_text_color(*C_VALUE)
        return w

    def divider():
        pdf.set_draw_color(220, 228, 236)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

    def safe_mc(txt, h=4.5):
        """multi_cell that ALWAYS resets x to left margin first."""
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(190, h, txt)

    # ====================================================================
    # COVER PAGE
    # ====================================================================
    pdf.add_page()
    pdf.set_fill_color(*C_DARK)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(0, 0, 210, 4, "F")

    pdf.set_fill_color(0, 130, 180)
    pdf.rect(82, 62, 46, 46, "F")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(82, 62, 46, 4, "F")
    pdf.set_font("Arial", "B", 28)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(82, 76)
    pdf.cell(46, 14, "CR", align="C")

    pdf.set_xy(0, 125)
    pdf.set_font("Arial", "B", 38)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(0, 16, "CORERECON", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.set_text_color(170, 170, 170)
    pdf.cell(0, 7, "INTELLIGENCE REPORT", ln=True, align="C")

    pdf.set_fill_color(25, 35, 50)
    pdf.rect(35, 163, 140, 32, "F")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(35, 163, 140, 2, "F")
    pdf.set_xy(35, 169)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(140, 5, "TARGET DOMAIN", align="C", ln=True)
    pdf.set_x(35)
    pdf.set_font("Arial", "B", 17)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(140, 9, st(target), align="C", ln=True)

    pdf.set_xy(0, 200)
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(*C_RISK)
    pdf.cell(0, 8, f"RISK: {risk_score}/100  {risk_level}", align="C")

    pdf.set_xy(0, 252)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 5, f"Generated: {timestamp}", ln=True, align="C")
    pdf.cell(0, 5, "Classification: TLP:WHITE - For Authorised Use Only", ln=True, align="C")

    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(0, 293, 210, 4, "F")
    pdf.set_xy(0, 280)
    pdf.set_font("Arial", "I", 7)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 5, "Powered by CoreRecon Intelligence Platform v2.3", align="C")

    # ====================================================================
    # PAGE 2 - EXECUTIVE SUMMARY
    # ====================================================================
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)

    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(*C_SECTION)
    pdf.cell(0, 10, "EXECUTIVE SUMMARY", ln=True)
    pdf.set_draw_color(*C_ACCENT)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(5)

    # scorecard row
    pdf.set_fill_color(245, 247, 252)
    pdf.rect(10, pdf.get_y(), 190, 22, "F")
    y_card = pdf.get_y()

    pdf.set_xy(18, y_card + 3)
    pdf.set_font("Arial", "B", 28)
    pdf.set_text_color(*C_RISK)
    pdf.cell(42, 12, f"{risk_score}", ln=False)
    pdf.set_xy(18, y_card + 15)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(*C_LABEL)
    pdf.cell(42, 4, "/ 100 RISK SCORE", ln=False)

    pdf.set_draw_color(210, 215, 225)
    pdf.line(62, y_card+3, 62, y_card+20)

    pdf.set_xy(66, y_card + 3)
    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(*C_RISK)
    pdf.cell(50, 9, st(risk_level), ln=False)
    pdf.set_xy(66, y_card + 13)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(*C_LABEL)
    pdf.cell(50, 4, "THREAT LEVEL", ln=False)

    pdf.line(118, y_card+3, 118, y_card+20)
    pdf.set_xy(122, y_card + 3)
    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(*C_DANGER)
    pdf.cell(30, 9, str(len(issues)), ln=False)
    pdf.set_xy(122, y_card + 13)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(*C_LABEL)
    pdf.cell(30, 4, "CRITICAL ISSUES", ln=False)

    pdf.line(155, y_card+3, 155, y_card+20)
    pdf.set_xy(159, y_card + 3)
    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(*C_SECTION)
    pdf.cell(30, 9, str(len(recommendations)), ln=False)
    pdf.set_xy(159, y_card + 13)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(*C_LABEL)
    pdf.cell(30, 4, "RECOMMENDATIONS", ln=False)

    pdf.ln(26)

    risk_status = data.get("risk_status")
    if risk_status:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_VALUE)
        safe_mc(st(risk_status), 4.5)
        pdf.ln(2)

    divider()

    # critical findings
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(*C_DANGER)
    pdf.cell(0, 5, f"CRITICAL FINDINGS  ({len(issues)})", ln=True)
    pdf.ln(1)
    if issues:
        for i, issue in enumerate(issues, 1):
            bg = C_ROWEVEN if i % 2 == 0 else (255, 248, 248)
            pdf.set_fill_color(*bg)
            y0 = pdf.get_y()
            pdf.rect(10, y0, 190, 8, "F")
            pdf.set_xy(13, y0 + 2)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(*C_DANGER)
            pdf.cell(7, 4, f"{i}.", ln=False)
            pdf.set_x(20)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(*C_VALUE)
            pdf.multi_cell(173, 4.5, st(issue))
    else:
        pdf.set_fill_color(240, 252, 244)
        pdf.rect(10, pdf.get_y(), 190, 8, "F")
        pdf.set_xy(14, pdf.get_y() + 2)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(*C_SUCCESS)
        pdf.cell(0, 4, "No critical vulnerabilities detected", ln=True)

    pdf.ln(4)
    divider()

    if recommendations:
        pdf.set_font("Arial", "B", 9)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(0, 5, f"SECURITY RECOMMENDATIONS  ({len(recommendations)})", ln=True)
        pdf.ln(1)
        for i, rec in enumerate(recommendations[:6], 1):
            bg = C_ROWEVEN if i % 2 == 0 else (244, 250, 255)
            pdf.set_fill_color(*bg)
            y0 = pdf.get_y()
            pdf.rect(10, y0, 190, 8, "F")
            pdf.set_xy(13, y0 + 2)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(*C_SECTION)
            pdf.cell(7, 4, f"{i}.", ln=False)
            pdf.set_x(20)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(*C_VALUE)
            pdf.multi_cell(173, 4.5, st(rec))
        if len(recommendations) > 6:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(*C_LABEL)
            pdf.cell(0, 4, f"... and {len(recommendations)-6} more recommendations", ln=True)

    # table of contents
    need_space(55)
    pdf.ln(4)
    divider()
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(*C_SECTION)
    pdf.cell(0, 5, "REPORT CONTENTS", ln=True)
    pdf.ln(2)
    toc_sections = [
        ("01", "Infrastructure & Network Intelligence"),
        ("02", "System Fingerprint & Security Headers"),
        ("03", "SSL/TLS Certificate Information"),
        ("04", "DNS Records & Configuration"),
        ("05", "WHOIS & Domain Registration"),
        ("06", "Technology Stack & Web Framework"),
        ("07", "Subdomain Discovery & Enumeration"),
        ("08", "Web Archive History"),
        ("09", "Report Summary & Statistics"),
    ]
    for idx in range(0, len(toc_sections), 2):
        y0 = pdf.get_y()
        for col, (num, title) in enumerate(toc_sections[idx:idx+2]):
            x = 10 + col * 95
            pdf.set_xy(x, y0)
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_text_color(*C_ACCENT)
            pdf.cell(8, 5, num, ln=False)
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(*C_VALUE)
            pdf.cell(85, 5, st(title), ln=False)
        pdf.ln(5)

    # ====================================================================
    # SECTION 01 - INFRASTRUCTURE
    # ====================================================================
    need_space(50)
    pdf.ln(4)
    section("01. INFRASTRUCTURE & NETWORK INTELLIGENCE", f"Primary host analysis for {st(target)}")

    infra = _as_dict(data.get("infrastructure"))

    # FIX: infrastructure module returns online:bool, not status:str
    is_online = infra.get("online", False) or infra.get("status", "") == "ONLINE"
    if is_online:
        badge("ONLINE", *C_SUCCESS)
    elif infra.get("error"):
        badge("UNREACHABLE", *C_DANGER)
    else:
        badge("OFFLINE", *C_DANGER)
    pdf.ln(7)

    asn = infra.get("asn")
    if isinstance(asn, dict):
        asn_num, asn_org = asn.get("number", ""), asn.get("organization", "")
    elif asn:
        asn_num, asn_org = str(asn), ""
    else:
        asn_num, asn_org = "", ""

    loc = _as_dict(infra.get("location"))
    kv_grid([
        ("IP Address",     infra.get("ip", "")),
        ("Reverse DNS",    infra.get("reverse_dns", "")),
        ("ISP / Provider", infra.get("provider", infra.get("isp", ""))),
        ("Organization",   infra.get("organization", infra.get("org", ""))),
        ("ASN Number",     asn_num),
        ("ASN Org",        asn_org),
        ("City",           loc.get("city", "")),
        ("Region",         loc.get("region", "")),
        ("Country",        infra.get("country", loc.get("country", ""))),
        ("Cloud Provider", infra.get("cloud_provider", "")),
    ])

    # ====================================================================
    # SECTION 02 - FINGERPRINT
    # ====================================================================
    need_space(55)
    pdf.ln(4)
    section("02. SYSTEM FINGERPRINT & SECURITY HEADERS")

    fing = _as_dict(data.get("fingerprint"))
    kv_grid([
        ("Web Server",  fing.get("server", "")),
        ("Protocol",    fing.get("protocol", "")),
        ("HTTP Status", fing.get("status_code", "")),
        ("Powered By",  fing.get("powered_by", "")),
        ("Cookies Set", fing.get("cookies", "")),
    ])

    security_headers = _as_dict(fing.get("security"))
    if security_headers:
        pdf.ln(2)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(0, 5, "Security Header Analysis", ln=True)
        pdf.ln(1)
        pdf.set_fill_color(230, 235, 245)
        pdf.set_font("Arial", "B", 7.5)
        pdf.set_text_color(*C_VALUE)
        pdf.set_x(10)
        pdf.cell(140, 5.5, "Header", 0, 0, "L", True)
        pdf.cell(50, 5.5, "Status", 0, 1, "C", True)
        pdf.set_font("Arial", "", 7.5)
        for i, (head, val) in enumerate(security_headers.items()):
            bg = C_ROWEVEN if i % 2 == 0 else C_ROWODD
            pdf.set_fill_color(*bg)
            pdf.set_x(10)
            pdf.set_text_color(*C_VALUE)
            pdf.cell(140, 5, st(head.replace("-", " ").title()), 0, 0, "L", True)
            if val == "MISSING":
                pdf.set_fill_color(255, 243, 243)
                pdf.set_text_color(*C_DANGER)
                pdf.cell(50, 5, "MISSING", 0, 1, "C", True)
            else:
                pdf.set_fill_color(240, 252, 244)
                pdf.set_text_color(*C_SUCCESS)
                pdf.cell(50, 5, "SET", 0, 1, "C", True)
            pdf.set_text_color(*C_VALUE)

    # ====================================================================
    # SECTION 03 - SSL/TLS
    # ====================================================================
    need_space(45)
    pdf.ln(4)
    section("03. SSL/TLS CERTIFICATE INFORMATION")

    ssl_data = _as_dict(data.get("ssl_certificate"))
    if ssl_data and "error" not in ssl_data:
        days_remaining = ssl_data.get("days_remaining", 0)
        try:
            days_remaining = int(days_remaining)
        except (TypeError, ValueError):
            days_remaining = 0

        if days_remaining > 30:
            cert_status, cert_color = "VALID", C_SUCCESS
        elif days_remaining > 0:
            cert_status, cert_color = "EXPIRING SOON", C_WARN
        else:
            cert_status, cert_color = "EXPIRED", C_DANGER

        badge(cert_status, *cert_color)
        pdf.set_font("Arial", "", 7.5)
        pdf.set_text_color(*C_LABEL)
        pdf.cell(0, 5, f"   {days_remaining} days remaining", ln=True)
        pdf.ln(3)

        kv_grid([
            ("TLS Version",    ssl_data.get("tls_version", "")),
            ("Sig. Algorithm", ssl_data.get("signature_algorithm", "")),
            ("Valid From",     ssl_data.get("valid_from", "")),
            ("Valid Until",    ssl_data.get("valid_until", "")),
            ("Serial Number",  ssl_data.get("serial_number", "")),
            ("Days Remaining", days_remaining),
        ])
        pdf.ln(1)
        kv_full("Issuer",  ssl_data.get("issuer", ""))
        kv_full("Subject", ssl_data.get("subject", ""))

        sans = _as_list(ssl_data.get("subject_alternative_names"))
        if sans:
            pdf.ln(2)
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_text_color(*C_SECTION)
            pdf.cell(0, 5, f"Subject Alternative Names  ({len(sans)})", ln=True)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(*C_VALUE)
            shown_sans = sans[:30]
            for i in range(0, len(shown_sans), 3):
                for j in range(3):
                    if i + j < len(shown_sans):
                        pdf.set_x(10 + j * 63)
                        pdf.cell(63, 3.5, st(f"> {shown_sans[i+j]}"[:26]), ln=(j == 2 or i+j == len(shown_sans)-1))
                if i + 3 < len(shown_sans):
                    pass
                else:
                    pdf.ln(2)
            if len(sans) > 30:
                pdf.set_font("Arial", "I", 7)
                pdf.set_text_color(*C_LABEL)
                pdf.cell(0, 4, f"... and {len(sans)-30} more", ln=True)
    else:
        pdf.set_fill_color(255, 245, 245)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_DANGER)
        pdf.cell(0, 4, "No SSL/TLS certificate detected for this target", ln=True)

    # ====================================================================
    # SECTION 04 - DNS RECORDS
    # ====================================================================
    need_space(40)
    pdf.ln(4)
    section("04. DNS RECORDS & CONFIGURATION")

    dns_data = _as_dict(data.get("dns"))
    for r_type, records in dns_data.items():
        if not isinstance(records, list) or not records:
            continue
        first = str(records[0])
        if "Query failed" in first or "timeout" in first.lower():
            continue
        need_space(20)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(0, 5, f"{r_type}  ({len(records)})", ln=True)
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(*C_VALUE)
        shown = records[:20]
        for i in range(0, len(shown), 2):
            y0 = pdf.get_y()
            bg = C_ROWEVEN if (i // 2) % 2 == 0 else C_ROWODD
            pdf.set_fill_color(*bg)
            pdf.rect(10, y0, 190, 4, "F")
            pdf.set_xy(10, y0)
            pdf.cell(95, 4, st(f"  {shown[i]}"), ln=False)
            if i + 1 < len(shown):
                pdf.cell(95, 4, st(f"  {shown[i+1]}"), ln=True)
            else:
                pdf.ln(4)
        if len(records) > 20:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(*C_LABEL)
            pdf.cell(0, 3.5, f"  ... {len(records)-20} more records", ln=True)
        pdf.ln(2)

    # ====================================================================
    # SECTION 05 - WHOIS
    # ====================================================================
    need_space(40)
    pdf.ln(4)
    section("05. WHOIS & DOMAIN REGISTRATION")

    whois_data = _as_dict(data.get("whois"))
    if not whois_data.get("error"):
        kv_grid([
            ("Registrar",          whois_data.get("registrar", "")),
            ("Organization",       whois_data.get("organization", "")),
            ("Registrant Country", whois_data.get("registrant_country", "")),
            ("DNSSEC",             whois_data.get("dnssec", "")),
            ("Created",            whois_data.get("creation_date", "")),
            ("Last Updated",       whois_data.get("updated_date", "")),
            ("Expires",            whois_data.get("expiration_date", "")),
        ])
        ns_list = _as_list(whois_data.get("name_servers"))
        if ns_list:
            pdf.ln(2)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(*C_SECTION)
            pdf.cell(0, 5, f"Name Servers  ({len(ns_list)})", ln=True)
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(*C_VALUE)
            for i in range(0, min(len(ns_list), 8), 2):
                y0 = pdf.get_y()
                bg = C_ROWEVEN if (i // 2) % 2 == 0 else C_ROWODD
                pdf.set_fill_color(*bg)
                pdf.rect(10, y0, 190, 4, "F")
                pdf.set_xy(10, y0)
                pdf.cell(95, 4, st(f"> {ns_list[i]}"), ln=False)
                if i + 1 < len(ns_list):
                    pdf.cell(95, 4, st(f"> {ns_list[i+1]}"), ln=True)
                else:
                    pdf.ln(4)
    else:
        note = whois_data.get("note", "WHOIS data unavailable or privacy protected")
        pdf.set_fill_color(255, 251, 240)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_WARN)
        pdf.cell(0, 4, st(note), ln=True)

    # ====================================================================
    # SECTION 06 - TECHNOLOGY STACK
    # ====================================================================
    need_space(40)
    pdf.ln(4)
    section("06. TECHNOLOGY STACK & WEB FRAMEWORK")

    raw_tech = data.get("technology")
    if isinstance(raw_tech, list):
        tech_data_norm = {"Detected": raw_tech}
    elif isinstance(raw_tech, dict):
        tech_data_norm = raw_tech
    else:
        tech_data_norm = {}

    skip_keys = {"message", "error", "status", "note"}
    renderable = {k: v for k, v in tech_data_norm.items()
                  if k not in skip_keys and isinstance(v, list) and v}

    if renderable:
        for category, items in renderable.items():
            need_space(20)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(*C_SECTION)
            pdf.cell(0, 5, f"{st(str(category).title())}  ({len(items)})", ln=True)
            pdf.set_fill_color(230, 235, 245)
            pdf.set_font("Arial", "B", 7)
            pdf.set_text_color(*C_VALUE)
            pdf.set_x(10)
            pdf.cell(100, 5, "Technology", 0, 0, "L", True)
            pdf.cell(40,  5, "Version",    0, 0, "C", True)
            pdf.cell(50,  5, "EOL Risk",   0, 1, "C", True)
            pdf.set_font("Arial", "", 7)
            for i, item in enumerate(items[:20]):
                bg = C_ROWEVEN if i % 2 == 0 else C_ROWODD
                pdf.set_fill_color(*bg)
                if isinstance(item, dict):
                    name = item.get("name", "Unknown")
                    ver  = item.get("version", "") or ""
                    eol  = item.get("eol_risk", "")
                    eol_note = item.get("eol_note", "")
                    y0 = pdf.get_y()
                    pdf.rect(10, y0, 190, 4.5, "F")
                    pdf.set_xy(10, y0 + 0.5)
                    pdf.set_text_color(*C_VALUE)
                    pdf.cell(98, 3.5, st(name), ln=False)
                    pdf.set_font("Courier", "", 6.5)
                    pdf.set_text_color(*C_SECTION if ver else C_LABEL)
                    pdf.cell(42, 3.5, st(ver if ver else "-"), ln=False, align="C")
                    pdf.set_font("Arial", "", 7)
                    if eol == "HIGH":
                        pdf.set_text_color(*C_DANGER)
                        pdf.cell(50, 3.5, st(f"HIGH - {eol_note}"[:30]), ln=True, align="C")
                    elif eol == "MEDIUM":
                        pdf.set_text_color(*C_WARN)
                        pdf.cell(50, 3.5, st(f"MED - {eol_note}"[:30]), ln=True, align="C")
                    elif eol == "LOW":
                        pdf.set_text_color(*C_SUCCESS)
                        pdf.cell(50, 3.5, "LOW", ln=True, align="C")
                    else:
                        pdf.set_text_color(*C_LABEL)
                        pdf.cell(50, 3.5, "-", ln=True, align="C")
                else:
                    pdf.rect(10, pdf.get_y(), 190, 4.5, "F")
                    pdf.set_xy(10, pdf.get_y() + 0.5)
                    pdf.set_text_color(*C_VALUE)
                    pdf.cell(190, 3.5, st(str(item)), ln=True)
            if len(items) > 20:
                pdf.set_font("Arial", "I", 7)
                pdf.set_text_color(*C_LABEL)
                pdf.cell(0, 4, f"  ... {len(items)-20} more items", ln=True)
            pdf.ln(3)
    else:
        pdf.set_fill_color(248, 248, 252)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_LABEL)
        pdf.cell(0, 4, "No technology signatures identified", ln=True)

    # ====================================================================
    # SECTION 07 - SUBDOMAINS
    # ====================================================================
    need_space(40)
    pdf.ln(4)
    section("07. SUBDOMAIN DISCOVERY & ENUMERATION")

    subs = _as_dict(data.get("subdomains"))
    sub_list = _as_list(subs.get("subdomains"))
    # FIX: API returns total_found, not count
    sub_count = subs.get("total_found", subs.get("count", len(sub_list)))

    pdf.set_fill_color(245, 247, 252)
    pdf.rect(10, pdf.get_y(), 190, 8, "F")
    pdf.set_xy(14, pdf.get_y() + 2)
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(*C_SECTION)
    pdf.cell(50, 4, f"{sub_count} Subdomains", ln=False)
    sources = _as_list(subs.get("sources"))
    if sources:
        pdf.set_font("Arial", "", 7.5)
        pdf.set_text_color(*C_LABEL)
        pdf.cell(0, 4, f"Sources: {', '.join(sources)}", ln=True)
    else:
        pdf.ln(4)
    pdf.ln(4)

    if sub_list:
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(*C_VALUE)
        # FIX: 2-column layout (95mm each, 42-char labels) instead of
        #      3-column (63mm each, 26-char labels) which truncated mid-word
        shown_subs = sub_list[:60]
        for i in range(0, len(shown_subs), 2):
            y0 = pdf.get_y()
            bg = C_ROWEVEN if (i // 2) % 2 == 0 else C_ROWODD
            pdf.set_fill_color(*bg)
            pdf.rect(10, y0, 190, 4, "F")
            for j in range(2):
                idx2 = i + j
                if idx2 < len(shown_subs):
                    label = f" {idx2+1}. {shown_subs[idx2]}"
                    pdf.set_xy(10 + j * 95, y0)
                    pdf.cell(95, 4, st(label[:42]), ln=False)
            pdf.ln(4)
        if len(sub_list) > 60:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(*C_LABEL)
            pdf.cell(0, 4, f"... and {len(sub_list)-60} additional subdomains not shown", ln=True)
    else:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_LABEL)
        pdf.cell(0, 5, "No subdomains discovered during reconnaissance", ln=True)

    # ====================================================================
    # SECTION 08 - WEB ARCHIVE
    # ====================================================================
    need_space(35)
    pdf.ln(4)
    section("08. WEB ARCHIVE HISTORY  (Wayback Machine)")

    wb = _as_dict(data.get("wayback"))
    if wb.get("available"):
        pdf.set_fill_color(242, 252, 246)
        pdf.rect(10, pdf.get_y(), 190, 8, "F")
        pdf.set_xy(14, pdf.get_y() + 2)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(*C_SUCCESS)
        pdf.cell(0, 4, "Historical archives available", ln=True)
        pdf.ln(2)
        kv_grid([
            ("Total Snapshots", wb.get("total_snapshots", "")),
            ("Last Captured",   wb.get("last_snapshot_formatted", wb.get("last_snapshot", ""))),
            ("Archive Status",  wb.get("status_code", "")),
        ])
        if wb.get("archive_url"):
            pdf.ln(1)
            kv_full("Latest Snapshot", wb["archive_url"], color=C_SECTION)
    else:
        msg = wb.get("message", "No historical archives found for this domain")
        pdf.set_fill_color(255, 251, 240)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(*C_WARN)
        pdf.set_x(14)
        pdf.multi_cell(176, 4, st(msg))

    # ====================================================================
    # SECTION 09 - SUMMARY
    # ====================================================================
    need_space(55)
    pdf.ln(4)
    section("09. REPORT SUMMARY & CONCLUSION")

    pdf.set_fill_color(245, 247, 252)
    pdf.rect(10, pdf.get_y(), 190, 18, "F")
    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.set_font("Arial", "B", 8)
    pdf.set_text_color(*C_VALUE)
    pdf.cell(0, 4.5, "Final Security Assessment", ln=True)
    pdf.set_font("Arial", "", 7.5)
    pdf.set_text_color(*C_LABEL)
    safe_mc(
        st(
            f"Target '{target}' received a risk score of {risk_score}/100 "
            f"with threat classification: {risk_level}. This assessment is based on "
            f"passive reconnaissance and should form part of a comprehensive security "
            f"evaluation programme."
        ),
        4.5
    )
    pdf.ln(4)
    divider()

    tech_count = sum(len(v) for v in renderable.values()) if renderable else 0
    dns_active  = sum(1 for v in dns_data.values() if isinstance(v, list) and v)

    pdf.set_font("Arial", "B", 8)
    pdf.set_text_color(*C_SECTION)
    pdf.cell(0, 5, "Reconnaissance Statistics", ln=True)
    pdf.ln(1)
    kv_grid([
        ("Total Issues Found",       len(issues)),
        ("Security Recommendations", len(recommendations)),
        ("Subdomains Discovered",    sub_count),   # FIX: now uses corrected sub_count
        ("DNS Record Types",         dns_active),
        ("Technologies Identified",  tech_count),
        ("Report Generated",         timestamp),
    ])

    pdf.ln(4)
    divider()

    pdf.set_font("Arial", "I", 7)
    pdf.set_text_color(*C_LABEL)
    safe_mc(
        "DISCLAIMER: This report contains information gathered through passive reconnaissance "
        "techniques and is intended for authorised security testing and research purposes only. "
        "Accuracy may vary based on target configuration at time of scanning. Always obtain "
        "proper authorisation before conducting security assessments.",
        4
    )

    pdf.ln(4)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(160, 160, 160)
    pdf.cell(
        0, 4,
        f"CoreRecon v2.3  |  "
        f"Report ID: CR-{target.replace('.', '-').upper()}-{datetime.now().strftime('%Y%m%d')}",
        ln=True, align="C"
    )

    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(0, 293, 210, 4, "F")

    return bytes(pdf.output())
