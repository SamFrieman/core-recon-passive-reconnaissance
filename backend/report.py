"""
CoreRecon v2.2 — PDF Report Generator
Called by main.py as:
    from backend.report import generate_pdf_report
    pdf_bytes = generate_pdf_report(scan_data)
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


class ReconPDF(FPDF):
    """FPDF subclass that adds automatic page numbers to all pages after the cover."""
    def footer(self):
        if self.page_no() > 1:
            self.set_y(-12)
            self.set_font("Arial", "I", 7)
            self.set_text_color(158, 158, 158)
            self.cell(0, 4, f"CoreRecon Intelligence Report  |  Page {self.page_no()}", align="C")
            self.set_draw_color(0, 200, 255)
            self.line(10, self.get_y() + 5, 200, self.get_y() + 5)


def generate_pdf_report(data: dict) -> bytes:
    """Generate a full intelligence PDF report. Returns raw PDF bytes."""
    if not isinstance(data, dict):
        data = {}

    clean_domain = data.get("target", "unknown")

    risk_score      = data.get("risk_score", 0)
    risk_level      = data.get("risk_level", "UNKNOWN")
    issues          = _as_list(data.get("risk_issues"))
    recommendations = _as_list(data.get("recommendations"))
    infra           = _as_dict(data.get("infrastructure"))
    fing            = _as_dict(data.get("fingerprint"))
    ssl_data        = _as_dict(data.get("ssl_certificate"))
    dns_data        = _as_dict(data.get("dns"))
    whois_data      = _as_dict(data.get("whois"))
    wb              = _as_dict(data.get("wayback"))
    subs            = _as_dict(data.get("subdomains"))
    sub_list        = _as_list(subs.get("subdomains"))
    sub_count       = subs.get("count", len(sub_list))

    raw_tech = data.get("technology")
    if isinstance(raw_tech, list):
        tech_data = {"detected": raw_tech}
    elif isinstance(raw_tech, dict):
        tech_data = raw_tech
    else:
        tech_data = {}
    _skip = {"message", "error", "status", "note"}
    renderable = {k: v for k, v in tech_data.items() if k not in _skip and isinstance(v, list)}
    tech_count = sum(len(v) for v in renderable.values())

    try:
        _s = int(risk_score)
    except (TypeError, ValueError):
        _s = 0
    if   _s <= 20: grade, grade_bg = "A", (0, 170, 90)
    elif _s <= 40: grade, grade_bg = "B", (80, 180, 80)
    elif _s <= 55: grade, grade_bg = "C", (210, 180, 0)
    elif _s <= 70: grade, grade_bg = "D", (210, 120, 0)
    elif _s <= 85: grade, grade_bg = "E", (205, 70, 30)
    else:          grade, grade_bg = "F", (210, 40, 40)

    if risk_level in ("MINIMAL", "LOW"):
        score_bg = (0, 155, 90)
    elif risk_level == "MEDIUM":
        score_bg = (195, 130, 0)
    else:
        score_bg = (205, 50, 50)

    pdf = ReconPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── helpers ──────────────────────────────────────────────────────────

    def safe(text) -> str:
        return str(text).encode("latin-1", "replace").decode("latin-1")

    def need_space(h: float):
        if pdf.get_y() + h > 272:
            pdf.add_page()

    def section_header(num: str, title: str, min_space: float = 60):
        need_space(min_space)
        y = pdf.get_y()
        pdf.set_fill_color(18, 28, 38)
        pdf.rect(10, y, 190, 8, "F")
        pdf.set_fill_color(0, 200, 255)
        pdf.rect(10, y, 3, 8, "F")
        pdf.set_font("Arial", "B", 9)
        pdf.set_text_color(0, 200, 255)
        pdf.set_xy(15, y + 1.5)
        pdf.cell(20, 5, safe(num), ln=False)
        pdf.set_text_color(215, 228, 242)
        pdf.cell(0, 5, safe(title.upper()), ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    def divider(light=False):
        c = 218 if light else 192
        pdf.set_draw_color(c, c, c)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2.5)

    def subsection(title: str):
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(0, 135, 185)
        pdf.cell(0, 5, safe(title.upper()), ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(0.5)

    def kv(key: str, val, highlight=False, left_w=48):
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(left_w, 4.5, safe(key + ":"), ln=False)
        pdf.set_font("Arial", "B" if highlight else "", 8)
        pdf.set_text_color(0, 135, 185) if highlight else pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 4.5, safe(str(val)), ln=True)
        pdf.set_text_color(0, 0, 0)

    def kv2(k1, v1, k2, v2, h1=False, h2=False):
        y0 = pdf.get_y()
        col = 95
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(110, 110, 110)
        pdf.set_xy(10, y0)
        pdf.cell(38, 4.5, safe(k1 + ":"), ln=False)
        pdf.set_font("Arial", "B" if h1 else "", 8)
        pdf.set_text_color(0, 135, 185) if h1 else pdf.set_text_color(50, 50, 50)
        pdf.cell(col - 38, 4.5, safe(str(v1)), ln=False)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(110, 110, 110)
        pdf.set_xy(10 + col, y0)
        pdf.cell(38, 4.5, safe(k2 + ":"), ln=False)
        pdf.set_font("Arial", "B" if h2 else "", 8)
        pdf.set_text_color(0, 135, 185) if h2 else pdf.set_text_color(50, 50, 50)
        pdf.cell(col - 38, 4.5, safe(str(v2)), ln=True)
        pdf.set_text_color(0, 0, 0)

    def stat_box(x, y, w, h, label, value, bg):
        pdf.set_fill_color(*bg)
        pdf.rect(x, y, w, h, "F")
        pdf.set_font("Arial", "B", 15)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(x, y + 2.5)
        pdf.cell(w, 8, safe(str(value)), align="C", ln=False)
        pdf.set_font("Arial", "", 6.5)
        pdf.set_text_color(220, 230, 240)
        pdf.set_xy(x, y + 11)
        pdf.cell(w, 4, safe(label.upper()), align="C", ln=False)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # COVER PAGE
    # ====================================================================
    pdf.set_fill_color(12, 18, 28)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_fill_color(0, 200, 255)
    pdf.rect(0, 0, 210, 4, "F")
    pdf.rect(0, 293, 210, 4, "F")

    pdf.set_fill_color(0, 140, 190)
    pdf.rect(83, 56, 44, 44, "F")
    pdf.set_fill_color(0, 100, 140)
    pdf.rect(83, 56, 44, 4, "F")
    pdf.set_font("Arial", "B", 28)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(83, 71)
    pdf.cell(44, 12, "CR", align="C")

    pdf.set_xy(0, 114)
    pdf.set_font("Arial", "B", 38)
    pdf.set_text_color(0, 200, 255)
    pdf.cell(0, 16, "CORERECON", align="C", ln=True)
    pdf.set_font("Arial", "", 13)
    pdf.set_text_color(155, 170, 188)
    pdf.cell(0, 7, "INTELLIGENCE REPORT", align="C", ln=True)

    pdf.set_fill_color(22, 34, 48)
    pdf.rect(35, 148, 140, 36, "F")
    pdf.set_fill_color(0, 200, 255)
    pdf.rect(35, 148, 140, 3, "F")
    pdf.set_xy(35, 155)
    pdf.set_font("Arial", "B", 9)
    pdf.set_text_color(95, 125, 155)
    pdf.cell(140, 5, "TARGET DOMAIN", align="C", ln=True)
    pdf.set_xy(35, 161)
    pdf.set_font("Arial", "B", 17)
    pdf.set_text_color(0, 200, 255)
    pdf.cell(140, 9, safe(data.get("target", clean_domain)), align="C", ln=True)
    pdf.set_xy(35, 171)
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(75, 100, 125)
    pdf.cell(140, 5, safe(f"Risk Score: {risk_score}/100  |  Grade: {grade}  |  Threat Level: {risk_level}"), align="C")

    pdf.set_xy(0, 198)
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(115, 132, 150)
    ts = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    pdf.cell(0, 5, f"Generated: {ts}", align="C", ln=True)
    pdf.cell(0, 5, "Classification: TLP:WHITE  —  For Authorised Use Only", align="C", ln=True)
    pdf.cell(0, 5, safe(f"Report ID: CR-{clean_domain.replace('.', '-').upper()}-{datetime.now().strftime('%Y%m%d')}"), align="C", ln=True)

    total_w = 4 * 40 + 3 * 5
    sx = (210 - total_w) / 2
    sy = 222
    stat_box(sx,       sy, 40, 22, "Risk Score",    f"{risk_score}/100",            score_bg)
    stat_box(sx + 45,  sy, 40, 22, "Issues Found",  len(issues),                   (195, 55, 55) if issues else (0, 145, 85))
    stat_box(sx + 90,  sy, 40, 22, "Subdomains",    sub_count,                     (0, 100, 158))
    stat_box(sx + 135, sy, 40, 22, "Technologies",  tech_count,                    (55, 78, 112))

    # ====================================================================
    # EXECUTIVE SUMMARY
    # ====================================================================
    pdf.add_page()

    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(0, 148, 198)
    pdf.cell(0, 9, "EXECUTIVE SUMMARY", ln=True)
    pdf.set_draw_color(0, 200, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    panel_y = pdf.get_y()
    pdf.set_fill_color(238, 244, 252)
    pdf.rect(10, panel_y, 190, 26, "F")
    pdf.set_xy(18, panel_y + 5)
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, "OVERALL THREAT LEVEL", ln=True)
    pdf.set_x(18)
    pdf.set_font("Arial", "B", 26)
    if risk_level in ("MINIMAL", "LOW"):
        pdf.set_text_color(0, 165, 85)
    elif risk_level == "MEDIUM":
        pdf.set_text_color(210, 138, 0)
    else:
        pdf.set_text_color(210, 48, 48)
    pdf.cell(44, 10, f"{risk_score}/100", ln=False)
    pdf.set_font("Arial", "B", 18)
    pdf.cell(40, 10, safe(risk_level), ln=False)
    pdf.set_fill_color(*grade_bg)
    pdf.rect(178, panel_y + 4, 16, 16, "F")
    pdf.set_font("Arial", "B", 15)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(178, panel_y + 7)
    pdf.cell(16, 10, grade, align="C")
    pdf.set_xy(18, panel_y + 20)
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(75, 80, 88)
    pdf.cell(0, 4, safe(data.get("risk_status", "Assessment complete.")), ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    divider()
    pdf.set_font("Arial", "B", 10)
    pdf.set_text_color(205, 48, 48)
    pdf.cell(0, 6, f"CRITICAL FINDINGS  ({len(issues)})", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)

    if issues:
        for i, issue in enumerate(issues, 1):
            need_space(10)
            ry = pdf.get_y()
            pdf.set_fill_color(255, 243, 243)
            pdf.rect(10, ry, 190, 7, "F")
            pdf.set_fill_color(205, 48, 48)
            pdf.rect(10, ry, 2, 7, "F")
            pdf.set_xy(15, ry + 1.5)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(158, 58, 58)
            pdf.cell(8, 4, f"{i}.", ln=False)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(58, 58, 58)
            pdf.multi_cell(172, 4, safe(issue))
    else:
        ry = pdf.get_y()
        pdf.set_fill_color(235, 252, 240)
        pdf.rect(10, ry, 190, 8, "F")
        pdf.set_xy(15, ry + 2)
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(0, 138, 78)
        pdf.cell(0, 4, "No critical vulnerabilities detected", ln=True)

    pdf.ln(3)

    if recommendations:
        need_space(20)
        divider()
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 138, 188)
        pdf.cell(0, 6, f"SECURITY RECOMMENDATIONS  ({len(recommendations)})", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        for i, rec in enumerate(recommendations, 1):
            need_space(10)
            ry = pdf.get_y()
            pdf.set_fill_color(236, 248, 255)
            pdf.rect(10, ry, 190, 7, "F")
            pdf.set_fill_color(0, 158, 208)
            pdf.rect(10, ry, 2, 7, "F")
            pdf.set_xy(15, ry + 1.5)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(0, 98, 148)
            pdf.cell(8, 4, f"{i}.", ln=False)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(48, 48, 48)
            pdf.multi_cell(172, 4, safe(rec))

    narrative = _as_dict(data.get("executive_summary"))
    if narrative:
        need_space(25)
        pdf.ln(2)
        divider()
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 138, 188)
        pdf.cell(0, 6, "INTELLIGENCE NARRATIVE", ln=True)
        for key in ("overview", "attack_surface", "exposure_summary", "recommendation_summary"):
            val = narrative.get(key)
            if val:
                need_space(12)
                pdf.set_font("Arial", "B", 8)
                pdf.set_text_color(78, 78, 78)
                pdf.cell(0, 4.5, safe(key.replace("_", " ").title() + ":"), ln=True)
                pdf.set_font("Arial", "", 8)
                pdf.set_text_color(52, 52, 52)
                pdf.multi_cell(0, 4, safe(str(val)))
                pdf.ln(1)

    # ====================================================================
    # 01. INFRASTRUCTURE & NETWORK
    # ====================================================================
    pdf.add_page()
    section_header("01", "Infrastructure & Network Intelligence")

    infra_status = infra.get("status", "UNKNOWN")
    s_bg = (0, 160, 88) if infra_status == "ONLINE" else (205, 58, 58)
    sy2 = pdf.get_y()
    pdf.set_fill_color(*s_bg)
    pdf.rect(10, sy2, 48, 7, "F")
    pdf.set_font("Arial", "B", 8)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(10, sy2 + 1)
    pdf.cell(48, 5, safe(f"STATUS: {infra_status}"), align="C", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    kv2("IP Address",   infra.get("ip", "N/A"),       "Reverse DNS",  infra.get("reverse_dns", "N/A"), h1=True)
    kv2("ISP Provider", infra.get("provider", "N/A"), "Organization", infra.get("organization", "N/A"))

    loc = _as_dict(infra.get("location"))
    city_region = f"{loc.get('city','?')}, {loc.get('region','?')}" if loc else "N/A"
    kv2("Country",      loc.get("country", "N/A") if loc else "N/A", "City / Region", city_region)
    if loc.get("coordinates"):
        kv("Coordinates", loc["coordinates"])

    asn = infra.get("asn")
    if isinstance(asn, dict):
        kv2("ASN Number", asn.get("number", "N/A"), "ASN Organization", asn.get("organization", "N/A"))
    elif asn:
        kv("ASN", str(asn))

    # ====================================================================
    # 02. SYSTEM FINGERPRINT & SECURITY HEADERS
    # ====================================================================
    need_space(72)
    pdf.ln(3)
    section_header("02", "System Fingerprint & Security Headers", min_space=72)

    kv2("Web Server",  fing.get("server", "Hidden/Unknown"), "Protocol",    fing.get("protocol", "N/A"), h2=True)
    kv2("HTTP Status", fing.get("status_code", "N/A"),       "Powered By",  fing.get("powered_by", "Not Disclosed"))
    kv2("Cookies Set", fing.get("cookies", 0),               "Redirect",    fing.get("redirect_chain", "None"))
    pdf.ln(3)

    subsection("Security Header Analysis")
    security_headers = _as_dict(fing.get("security"))

    if security_headers:
        th_y = pdf.get_y()
        pdf.set_fill_color(26, 38, 52)
        pdf.rect(10, th_y, 190, 6, "F")
        pdf.set_font("Arial", "B", 7.5)
        pdf.set_text_color(195, 212, 228)
        pdf.set_xy(13, th_y + 1)
        pdf.cell(130, 4, "SECURITY HEADER", ln=False)
        pdf.cell(0,   4, "STATUS", align="C", ln=True)
        pdf.set_text_color(0, 0, 0)
        alt = False
        for head, val in security_headers.items():
            need_space(7)
            ry = pdf.get_y()
            present = val not in ("MISSING", None, "")
            if present:
                pdf.set_fill_color(240, 250, 242) if not alt else pdf.set_fill_color(234, 246, 236)
            else:
                pdf.set_fill_color(255, 244, 244) if not alt else pdf.set_fill_color(252, 240, 240)
            pdf.rect(10, ry, 190, 5.5, "F")
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(58, 58, 58)
            pdf.set_xy(13, ry + 1)
            pdf.cell(130, 3.5, safe(head.replace("-", " ").upper()), ln=False)
            lbl = "PRESENT" if present else "MISSING"
            pdf.set_text_color(0, 138, 78) if present else pdf.set_text_color(188, 38, 38)
            pdf.set_font("Arial", "B", 7.5)
            pdf.cell(0, 3.5, lbl, align="C", ln=True)
            pdf.set_text_color(0, 0, 0)
            alt = not alt

    # ====================================================================
    # 03. SSL / TLS CERTIFICATE
    # ====================================================================
    need_space(62)
    pdf.ln(3)
    section_header("03", "SSL / TLS Certificate", min_space=62)

    if "error" not in ssl_data and ssl_data:
        days = ssl_data.get("days_remaining", 0)
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 0

        if days > 30:
            cert_bg, cert_lbl = (0, 160, 88), "VALID"
        elif days > 0:
            cert_bg, cert_lbl = (205, 138, 0), "EXPIRING SOON"
        else:
            cert_bg, cert_lbl = (205, 48, 48), "EXPIRED"

        cy = pdf.get_y()
        pdf.set_fill_color(*cert_bg)
        pdf.rect(10, cy, 58, 7, "F")
        pdf.set_font("Arial", "B", 8)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(10, cy + 1)
        pdf.cell(58, 5, safe(f"CERTIFICATE: {cert_lbl}"), align="C", ln=False)
        pdf.set_fill_color(232, 244, 252)
        pdf.rect(70, cy, 55, 7, "F")
        pdf.set_text_color(0, 118, 175)
        pdf.set_xy(70, cy + 1)
        pdf.cell(55, 5, f"{days} days remaining", align="C", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

        kv2("TLS Version",   ssl_data.get("tls_version", "N/A"),  "Sig. Algorithm", ssl_data.get("signature_algorithm", "N/A"), h1=True)
        kv2("Valid From",    ssl_data.get("valid_from", "N/A"),    "Valid Until",    ssl_data.get("valid_until", "N/A"))
        kv2("Serial Number", ssl_data.get("serial_number", "N/A"),"Grade",          ssl_data.get("grade", "N/A"), h2=True)
        if ssl_data.get("issuer"):
            kv("Issuer",  ssl_data.get("issuer",  "N/A"), left_w=30)
        if ssl_data.get("subject"):
            kv("Subject", ssl_data.get("subject", "N/A"), left_w=30)

        sans = _as_list(ssl_data.get("subject_alternative_names"))
        if sans:
            pdf.ln(2)
            subsection(f"Subject Alternative Names  ({len(sans)})")
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(52, 52, 52)
            col_w = 190 / 3
            for i in range(0, min(len(sans), 24), 3):
                pdf.set_x(12)
                for j in range(3):
                    if i + j < len(sans):
                        pdf.cell(col_w, 3.5, safe(f"> {sans[i+j]}"), ln=False)
                pdf.ln(3.5)
            if len(sans) > 24:
                pdf.set_font("Arial", "I", 7)
                pdf.set_text_color(128, 128, 128)
                pdf.cell(0, 3, f"... and {len(sans)-24} more", ln=True)
            pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_fill_color(255, 243, 243)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(15, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(175, 48, 48)
        pdf.cell(0, 4, "No SSL/TLS certificate detected for this target.", ln=True)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # 04. DNS RECORDS
    # ====================================================================
    need_space(52)
    pdf.ln(3)
    section_header("04", "DNS Records & Configuration", min_space=52)

    dns_printed = False
    for r_type, records in dns_data.items():
        if not isinstance(records, list) or not records:
            continue
        first = str(records[0])
        if "Query failed" in first or "timeout" in first.lower():
            continue
        dns_printed = True
        need_space(max(14, min(len(records), 8) * 4 + 12))
        subsection(f"{r_type} Records  ({len(records)})")
        pdf.set_font("Courier", "", 7.5)
        pdf.set_text_color(52, 52, 52)
        avg_len = sum(len(str(r)) for r in records[:6]) / max(len(records[:6]), 1)
        shown = records[:12]
        if avg_len < 30:
            for i in range(0, len(shown), 2):
                pdf.set_x(12)
                pdf.cell(93, 3.5, safe(f"> {shown[i]}"), ln=False)
                if i + 1 < len(shown):
                    pdf.cell(93, 3.5, safe(f"> {shown[i+1]}"), ln=True)
                else:
                    pdf.ln(3.5)
        else:
            for r in shown:
                pdf.set_x(12)
                pdf.cell(0, 3.5, safe(f"> {r}"), ln=True)
        if len(records) > 12:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(128, 128, 128)
            pdf.cell(0, 3, f"  ... and {len(records)-12} more", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    if not dns_printed:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(138, 138, 138)
        pdf.cell(0, 5, "No DNS records retrieved.", ln=True)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # 05. WHOIS + WEB ARCHIVE  (combined — both are compact)
    # ====================================================================
    need_space(58)
    pdf.ln(3)
    section_header("05", "WHOIS, Domain Registration & Web Archive", min_space=58)

    if not whois_data.get("error") and whois_data:
        kv2("Registrar",  whois_data.get("registrar", "N/A"),          "Organization", whois_data.get("organization", "Private/Redacted"), h1=True)
        kv2("Country",    whois_data.get("registrant_country", "N/A"), "DNSSEC",       whois_data.get("dnssec", "Unsigned"))
        kv2("Created",    whois_data.get("creation_date", "Unknown"),   "Last Updated", whois_data.get("updated_date", "Unknown"))
        kv2("Expires",    whois_data.get("expiration_date", "Unknown"), "Domain Age",   whois_data.get("domain_age", "N/A"))
        ns_list = _as_list(whois_data.get("name_servers"))
        if ns_list:
            pdf.ln(1)
            subsection(f"Name Servers  ({len(ns_list)})")
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(52, 52, 52)
            for i in range(0, min(len(ns_list), 8), 2):
                pdf.set_x(12)
                pdf.cell(93, 3.5, safe(f"> {ns_list[i]}"), ln=False)
                if i + 1 < len(ns_list):
                    pdf.cell(93, 3.5, safe(f"> {ns_list[i+1]}"), ln=True)
                else:
                    pdf.ln(3.5)
            pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(158, 128, 0)
        pdf.multi_cell(0, 4.5, safe(whois_data.get("note", "WHOIS data unavailable or privacy protected.")))
        pdf.set_text_color(0, 0, 0)

    need_space(26)
    pdf.ln(3)
    divider(light=True)
    subsection("Web Archive History (Wayback Machine)")

    if wb.get("available"):
        kv2("Total Snapshots", wb.get("total_snapshots", "N/A"),
            "Last Captured", wb.get("last_snapshot_formatted", wb.get("last_snapshot", "N/A")), h1=True)
        kv("Archive Status", wb.get("status_code", "N/A"))
        if wb.get("archive_url"):
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_text_color(98, 98, 98)
            pdf.cell(0, 4, "Latest Snapshot URL:", ln=True)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(0, 98, 188)
            pdf.multi_cell(0, 3.5, safe(wb["archive_url"]))
            pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(158, 128, 0)
        pdf.cell(0, 4.5, safe(wb.get("message", "No historical archives found for this domain.")), ln=True)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # 06. TECHNOLOGY STACK
    # ====================================================================
    need_space(48)
    pdf.ln(3)
    section_header("06", "Technology Stack & Web Frameworks", min_space=48)

    if renderable:
        for category, items in renderable.items():
            need_space(max(16, min(len(items), 10) * 7 + 14))
            cat_y = pdf.get_y()
            pdf.set_fill_color(232, 240, 252)
            pdf.rect(10, cat_y, 190, 6.5, "F")
            pdf.set_fill_color(0, 138, 188)
            pdf.rect(10, cat_y, 3, 6.5, "F")
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(28, 68, 118)
            pdf.set_xy(15, cat_y + 1.5)
            pdf.cell(0, 4, safe(str(category).upper()), ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)

            col_w = 190 / 3
            rows = [items[i:i+3] for i in range(0, min(len(items), 30), 3)]
            for ri, row in enumerate(rows):
                need_space(7)
                ry = pdf.get_y()
                for ci, item in enumerate(row):
                    x = 10 + ci * col_w
                    bg = (246, 250, 255) if ri % 2 == 0 else (240, 245, 252)
                    pdf.set_fill_color(*bg)
                    pdf.rect(x, ry, col_w, 6, "F")
                    pdf.set_xy(x + 2, ry + 1)
                    if isinstance(item, dict):
                        name = item.get("name", "Unknown")
                        ver  = item.get("version") or ""
                        eol  = item.get("eol_risk", "")
                        pdf.set_font("Arial", "B", 7.5)
                        pdf.set_text_color(42, 42, 42)
                        pdf.cell(col_w - 24, 4, safe(name), ln=False)
                        if ver and ver != "Undetected":
                            pdf.set_font("Courier", "", 6.5)
                            pdf.set_text_color(0, 128, 178)
                            pdf.cell(20, 4, safe(f"v{ver}"), ln=False)
                        else:
                            pdf.cell(20, 4, "", ln=False)
                        if eol and eol.lower() not in ("low", "none", ""):
                            pdf.set_font("Arial", "B", 7)
                            pdf.set_text_color(205, 48, 48)
                            pdf.cell(4, 4, "!", ln=False)
                    else:
                        pdf.set_font("Arial", "", 7.5)
                        pdf.set_text_color(52, 52, 52)
                        pdf.cell(col_w - 4, 4, safe(str(item)), ln=False)
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(6)

            if len(items) > 30:
                pdf.set_font("Arial", "I", 7)
                pdf.set_text_color(128, 128, 128)
                pdf.cell(0, 3, f"  ... and {len(items)-30} more in this category", ln=True)
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
    else:
        pdf.set_fill_color(244, 244, 250)
        pdf.rect(10, pdf.get_y(), 190, 10, "F")
        pdf.set_xy(15, pdf.get_y() + 3)
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 4, "No technology signatures identified.", ln=True)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # 07. SUBDOMAINS
    # ====================================================================
    need_space(48)
    pdf.ln(3)
    section_header("07", "Subdomain Discovery & Enumeration", min_space=48)

    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(0, 138, 188)
    pdf.cell(0, 7, f"{sub_count} Subdomains Discovered", ln=True)
    pdf.set_text_color(0, 0, 0)

    sources = _as_list(subs.get("sources"))
    if sources:
        pdf.set_font("Arial", "", 7.5)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 4, safe(f"Sources: {', '.join(str(s) for s in sources)}"), ln=True)
    pdf.ln(1)
    divider(light=True)

    if sub_list:
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(48, 52, 62)
        col_w = 190 / 3
        for i in range(0, min(len(sub_list), 90), 3):
            need_space(5)
            ry = pdf.get_y()
            for ci in range(3):
                idx = i + ci
                if idx < len(sub_list):
                    bg = (246, 249, 255) if ((i // 3) % 2 == 0) else (240, 244, 252)
                    x = 10 + ci * col_w
                    pdf.set_fill_color(*bg)
                    pdf.rect(x, ry, col_w, 4, "F")
                    pdf.set_xy(x + 2, ry + 0.5)
                    pdf.cell(col_w - 2, 3, safe(f"{idx+1}. {sub_list[idx]}"), ln=False)
            pdf.ln(4)
        if len(sub_list) > 90:
            pdf.set_font("Arial", "I", 7)
            pdf.set_text_color(128, 128, 128)
            pdf.cell(0, 3.5, f"... and {len(sub_list)-90} additional subdomains not shown", ln=True)
        pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(138, 138, 138)
        pdf.cell(0, 5, "No subdomains discovered during reconnaissance.", ln=True)
        pdf.set_text_color(0, 0, 0)

    # ====================================================================
    # FINAL PAGE — SUMMARY & STATISTICS
    # ====================================================================
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 138, 188)
    pdf.cell(0, 9, "REPORT SUMMARY & STATISTICS", ln=True)
    pdf.set_draw_color(0, 200, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_fill_color(240, 245, 252)
    pdf.rect(10, pdf.get_y(), 190, 30, "F")
    pdf.set_xy(18, pdf.get_y() + 5)
    pdf.set_font("Arial", "B", 10)
    pdf.set_text_color(58, 68, 80)
    pdf.cell(0, 5, "Final Security Assessment", ln=True)
    pdf.set_x(18)
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(78, 82, 90)
    pdf.multi_cell(
        172, 4.5,
        safe(
            f"Target '{data.get('target')}' was assigned a risk score of {risk_score}/100 "
            f"(Grade {grade}) with a threat classification of {risk_level}. "
            f"This assessment was produced using passive reconnaissance techniques only. "
            f"Always obtain proper authorisation before performing any active security testing."
        )
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    strip_y3 = pdf.get_y()
    stat_box(10,  strip_y3, 44, 22, "Risk Score",     f"{risk_score}/100", score_bg)
    stat_box(58,  strip_y3, 44, 22, "Critical Issues", len(issues),        (195, 52, 52) if issues else (0, 148, 85))
    stat_box(106, strip_y3, 44, 22, "Subdomains",      sub_count,          (0, 105, 162))
    stat_box(154, strip_y3, 46, 22, "Technologies",    tech_count,         (55, 78, 115))
    pdf.ln(28)
    divider()

    subsection("Reconnaissance Statistics")
    dns_retrieved   = sum(1 for v in dns_data.values() if isinstance(v, list) and v)
    missing_headers = sum(1 for v in _as_dict(fing.get("security")).values() if v == "MISSING")
    ssl_days        = ssl_data.get("days_remaining", "N/A") if ssl_data and "error" not in ssl_data else "N/A"

    kv2("Total Issues Found",        len(issues),      "Security Recommendations", len(recommendations))
    kv2("Subdomains Discovered",     sub_count,        "Technologies Identified",  tech_count)
    kv2("DNS Record Types",          dns_retrieved,    "Security Headers Missing", missing_headers)
    kv2("SSL Days Remaining",        ssl_days,         "Risk Grade",              grade)

    module_statuses = _as_dict(data.get("module_statuses"))
    module_timings  = _as_dict(data.get("module_timings"))
    if module_statuses:
        pdf.ln(4)
        divider()
        subsection("Module Execution Status")
        th_y = pdf.get_y()
        pdf.set_fill_color(26, 38, 52)
        pdf.rect(10, th_y, 190, 6, "F")
        pdf.set_font("Arial", "B", 7.5)
        pdf.set_text_color(195, 212, 228)
        pdf.set_xy(13, th_y + 1)
        pdf.cell(75, 4, "MODULE", ln=False)
        pdf.cell(75, 4, "STATUS", ln=False)
        pdf.cell(0,  4, "DURATION", ln=True)
        pdf.set_text_color(0, 0, 0)
        alt = False
        for mod, mstatus in module_statuses.items():
            need_space(7)
            ry = pdf.get_y()
            ok = mstatus in ("OK", "SOFT_FAIL")
            if ok:
                pdf.set_fill_color(240, 250, 242) if not alt else pdf.set_fill_color(234, 246, 236)
            else:
                pdf.set_fill_color(255, 244, 244) if not alt else pdf.set_fill_color(252, 240, 240)
            pdf.rect(10, ry, 190, 5.5, "F")
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(55, 55, 55)
            pdf.set_xy(13, ry + 1)
            pdf.cell(75, 3.5, safe(str(mod)), ln=False)
            color_map = {"OK": (0, 138, 78), "SOFT_FAIL": (188, 128, 0)}
            pdf.set_text_color(*color_map.get(mstatus, (192, 38, 38)))
            pdf.set_font("Arial", "B", 7.5)
            pdf.cell(75, 3.5, safe(str(mstatus)), ln=False)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(98, 98, 98)
            timing = module_timings.get(mod)
            pdf.cell(0, 3.5, safe(f"{timing:.2f}s" if isinstance(timing, (int, float)) else "-"), ln=True)
            pdf.set_text_color(0, 0, 0)
            alt = not alt

    pdf.ln(5)
    divider()
    pdf.set_font("Arial", "I", 7.5)
    pdf.set_text_color(128, 128, 128)
    pdf.multi_cell(
        0, 4,
        "DISCLAIMER: This report contains information gathered through passive reconnaissance "
        "techniques and is intended for authorised security testing and research purposes only. "
        "The accuracy of findings may vary based on target configuration and availability at the "
        "time of scanning. Always obtain proper authorisation before conducting security assessments."
    )

    return bytes(pdf.output())
