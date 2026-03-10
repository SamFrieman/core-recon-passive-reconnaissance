"""
CoreRecon Technology Stack Detection Module v3.0
Replaces python-wappalyzer with a self-contained HTTP fingerprinter.

Why the rewrite:
  - python-wappalyzer downloads fingerprint data at runtime → fails in prod
  - Library is largely unmaintained → import errors on newer Python
  - This module uses direct HTTP requests + regex/string pattern matching
  - Zero external dependencies beyond `requests` (already in requirements.txt)
  - Covers 60+ technologies across 15 categories
  - Preserves the exact same output structure: {category: [{name, version, eol_risk, eol_note}]}
"""
import re
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from backend.core.logger import get_logger

log = get_logger("corerecon.technology")

REQUEST_TIMEOUT = 12

# ---------------------------------------------------------------------------
# EOL version thresholds — same as v1 for risk scoring compatibility
# ---------------------------------------------------------------------------
EOL_INDICATORS = {
    "jquery":    {"below": (3, 0, 0), "note": "jQuery below 3.x has known XSS vulnerabilities"},
    "php":       {"below": (8, 1, 0), "note": "PHP versions below 8.1 are end-of-life"},
    "wordpress": {"below": (6, 0, 0), "note": "WordPress below 6.0 — update strongly recommended"},
    "bootstrap": {"below": (4, 0, 0), "note": "Bootstrap 3.x and below no longer receive security fixes"},
    "angularjs": {"below": (99, 0, 0), "note": "AngularJS (1.x) reached end-of-life December 2021"},
    "python":    {"below": (3, 8, 0), "note": "Python below 3.8 is end-of-life"},
    "drupal":    {"below": (9, 0, 0), "note": "Drupal 8.x and below are end-of-life"},
    "nginx":     {"below": (1, 18, 0), "note": "Nginx below 1.18 is end-of-life"},
    "apache":    {"below": (2, 4, 0), "note": "Apache below 2.4 is end-of-life"},
    "openssl":   {"below": (1, 1, 1), "note": "OpenSSL below 1.1.1 is end-of-life"},
}


def _parse_version(ver_str: str) -> Optional[Tuple[int, ...]]:
    """Parse a version string like '1.2.3' into a comparable tuple."""
    if not ver_str:
        return None
    try:
        parts = re.findall(r"\d+", ver_str)[:3]
        return tuple(int(p) for p in parts) if parts else None
    except Exception:
        return None


def _check_eol(name: str, version: str) -> Dict[str, Any]:
    key = name.lower().replace(" ", "").replace("-", "")
    parsed = _parse_version(version)
    if not parsed:
        return {"eol_risk": False, "eol_note": None}
    for tech_key, info in EOL_INDICATORS.items():
        if tech_key in key:
            if parsed < info["below"]:
                return {"eol_risk": True, "eol_note": info["note"]}
    return {"eol_risk": False, "eol_note": None}


# ---------------------------------------------------------------------------
# Detection rules
# Each rule: (category, name, patterns)
# patterns is a list of dicts with keys:
#   header     — check response header (header_name, regex_for_version_or_None)
#   meta       — check <meta> tags in HTML (regex)
#   html       — check raw HTML (regex, group=1 is version if present)
#   cookie     — check cookie names
#   script_src — check <script src=...> attributes
#   link_href  — check <link href=...> attributes
# ---------------------------------------------------------------------------

TECH_RULES: List[Dict] = [
    # ── Web Servers ──────────────────────────────────────────────────────────
    {
        "category": "Web Servers",
        "name": "Nginx",
        "patterns": [
            {"header": ("Server", re.compile(r"nginx[/\s]?([\d.]+)?", re.I))},
        ],
    },
    {
        "category": "Web Servers",
        "name": "Apache",
        "patterns": [
            {"header": ("Server", re.compile(r"Apache[/\s]?([\d.]+)?", re.I))},
        ],
    },
    {
        "category": "Web Servers",
        "name": "Microsoft IIS",
        "patterns": [
            {"header": ("Server", re.compile(r"Microsoft-IIS[/\s]?([\d.]+)?", re.I))},
        ],
    },
    {
        "category": "Web Servers",
        "name": "LiteSpeed",
        "patterns": [
            {"header": ("Server", re.compile(r"LiteSpeed", re.I))},
        ],
    },
    {
        "category": "Web Servers",
        "name": "Caddy",
        "patterns": [
            {"header": ("Server", re.compile(r"Caddy", re.I))},
        ],
    },
    {
        "category": "Web Servers",
        "name": "OpenResty",
        "patterns": [
            {"header": ("Server", re.compile(r"openresty[/\s]?([\d.]+)?", re.I))},
        ],
    },

    # ── Programming Languages / Runtimes ────────────────────────────────────
    {
        "category": "Programming Languages",
        "name": "PHP",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"PHP[/\s]?([\d.]+)", re.I))},
            {"header": ("Server", re.compile(r"PHP[/\s]?([\d.]+)", re.I))},
            {"html": re.compile(r"\.php(?:\?|\")", re.I)},
        ],
    },
    {
        "category": "Programming Languages",
        "name": "Python",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"Python[/\s]?([\d.]+)", re.I))},
            {"header": ("Server", re.compile(r"Python[/\s]?([\d.]+)", re.I))},
        ],
    },
    {
        "category": "Programming Languages",
        "name": "Node.js",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"Express", re.I))},
            {"header": ("Server", re.compile(r"Node\.js", re.I))},
        ],
    },
    {
        "category": "Programming Languages",
        "name": "Ruby",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"Phusion Passenger[/\s]?([\d.]+)?|Ruby", re.I))},
            {"header": ("Server", re.compile(r"Passenger[/\s]?([\d.]+)?", re.I))},
        ],
    },
    {
        "category": "Programming Languages",
        "name": "Java",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"Servlet|JSP|Tomcat|JBoss|Java", re.I))},
            {"header": ("Server", re.compile(r"Apache-Coyote|Tomcat|JBoss|Jetty[/\s]?([\d.]+)?", re.I))},
        ],
    },

    # ── Frameworks ──────────────────────────────────────────────────────────
    {
        "category": "Web Frameworks",
        "name": "Django",
        "patterns": [
            {"header": ("X-Frame-Options", re.compile(r"SAMEORIGIN", re.I))},
            {"cookie": "csrftoken"},
            {"html": re.compile(r"csrfmiddlewaretoken|django", re.I)},
        ],
    },
    {
        "category": "Web Frameworks",
        "name": "Laravel",
        "patterns": [
            {"cookie": "laravel_session"},
            {"header": ("Set-Cookie", re.compile(r"laravel_session", re.I))},
        ],
    },
    {
        "category": "Web Frameworks",
        "name": "Ruby on Rails",
        "patterns": [
            {"cookie": "_session_id"},
            {"header": ("X-Powered-By", re.compile(r"Phusion Passenger", re.I))},
            {"html": re.compile(r"rails-ujs|data-remote=\"true\"", re.I)},
        ],
    },
    {
        "category": "Web Frameworks",
        "name": "ASP.NET",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"ASP\.NET", re.I))},
            {"header": ("X-AspNet-Version", re.compile(r"([\d.]+)"))} ,
            {"cookie": "ASP.NET_SessionId"},
        ],
    },
    {
        "category": "Web Frameworks",
        "name": "Express.js",
        "patterns": [
            {"header": ("X-Powered-By", re.compile(r"Express", re.I))},
        ],
    },
    {
        "category": "Web Frameworks",
        "name": "FastAPI",
        "patterns": [
            {"header": ("Server", re.compile(r"uvicorn", re.I))},
            {"html": re.compile(r"fastapi|/openapi\.json", re.I)},
        ],
    },

    # ── CMS ─────────────────────────────────────────────────────────────────
    {
        "category": "CMS",
        "name": "WordPress",
        "patterns": [
            {"meta": re.compile(r'name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.I)},
            {"html": re.compile(r"/wp-content/|/wp-includes/|wp-json", re.I)},
            {"link_href": re.compile(r"/wp-content/themes/", re.I)},
        ],
    },
    {
        "category": "CMS",
        "name": "Drupal",
        "patterns": [
            {"meta": re.compile(r'name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]+)', re.I)},
            {"html": re.compile(r"Drupal\.settings|/sites/default/files/", re.I)},
            {"header": ("X-Generator", re.compile(r"Drupal\s*([\d.]+)", re.I))},
        ],
    },
    {
        "category": "CMS",
        "name": "Joomla",
        "patterns": [
            {"meta": re.compile(r'name=["\']generator["\'][^>]+content=["\']Joomla', re.I)},
            {"html": re.compile(r"/media/system/js/|com_content", re.I)},
        ],
    },
    {
        "category": "CMS",
        "name": "Ghost",
        "patterns": [
            {"meta": re.compile(r'name=["\']generator["\'][^>]+content=["\']Ghost\s*([\d.]+)', re.I)},
            {"html": re.compile(r"ghost-version|content\.ghost\.io", re.I)},
        ],
    },
    {
        "category": "CMS",
        "name": "Shopify",
        "patterns": [
            {"html": re.compile(r"Shopify\.theme|cdn\.shopify\.com", re.I)},
            {"header": ("X-ShopId", None)},
            {"header": ("X-Shopify-Stage", None)},
        ],
    },
    {
        "category": "CMS",
        "name": "Squarespace",
        "patterns": [
            {"html": re.compile(r"squarespace\.com|static\.squarespace\.com", re.I)},
            {"header": ("Server", re.compile(r"Squarespace", re.I))},
        ],
    },
    {
        "category": "CMS",
        "name": "Wix",
        "patterns": [
            {"html": re.compile(r"wix\.com|wixstatic\.com", re.I)},
        ],
    },
    {
        "category": "CMS",
        "name": "Webflow",
        "patterns": [
            {"html": re.compile(r"webflow\.com|assets\.website-files\.com", re.I)},
            {"header": ("X-Wf-Csrftoken", None)},
        ],
    },

    # ── JavaScript Frameworks / Libraries ────────────────────────────────────
    {
        "category": "JavaScript Frameworks",
        "name": "React",
        "patterns": [
            {"script_src": re.compile(r"react(?:\.min)?\.js|react-dom", re.I)},
            {"html": re.compile(r"__reactFiber|__reactInternalInstance|data-reactroot|data-reactid", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Vue.js",
        "patterns": [
            {"script_src": re.compile(r"vue(?:\.min)?\.js|vue@[\d]", re.I)},
            {"html": re.compile(r"__vue__|v-bind:|v-if=|v-for=|v-model=", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Angular",
        "patterns": [
            {"html": re.compile(r"ng-version=|ng-app=|angular\.min\.js|@angular/core", re.I)},
            {"script_src": re.compile(r"angular(?:\.min)?\.js", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "AngularJS",
        "patterns": [
            {"html": re.compile(r"ng-app=|ng-controller=|ng-model=|angularjs", re.I)},
            {"script_src": re.compile(r"angular(?:\.min)?\.js", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Next.js",
        "patterns": [
            {"html": re.compile(r"__NEXT_DATA__|/_next/static/", re.I)},
            {"header": ("X-Powered-By", re.compile(r"Next\.js", re.I))},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Nuxt.js",
        "patterns": [
            {"html": re.compile(r"__NUXT__|/_nuxt/", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Svelte",
        "patterns": [
            {"html": re.compile(r"__svelte|svelte-", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Ember.js",
        "patterns": [
            {"script_src": re.compile(r"ember(?:\.min)?\.js", re.I)},
            {"html": re.compile(r"ember-application|ember-view", re.I)},
        ],
    },
    {
        "category": "JavaScript Frameworks",
        "name": "Backbone.js",
        "patterns": [
            {"script_src": re.compile(r"backbone(?:\.min)?\.js", re.I)},
        ],
    },
    {
        "category": "JavaScript Libraries",
        "name": "jQuery",
        "patterns": [
            {"script_src": re.compile(r"jquery[.-]([\d.]+)(?:\.min)?\.js", re.I)},
            {"html": re.compile(r"jquery[.-]([\d.]+)(?:\.min)?\.js", re.I)},
        ],
    },
    {
        "category": "JavaScript Libraries",
        "name": "Lodash",
        "patterns": [
            {"script_src": re.compile(r"lodash(?:\.min)?\.js", re.I)},
            {"html": re.compile(r"lodash@([\d.]+)", re.I)},
        ],
    },
    {
        "category": "JavaScript Libraries",
        "name": "Moment.js",
        "patterns": [
            {"script_src": re.compile(r"moment(?:\.min)?\.js", re.I)},
        ],
    },
    {
        "category": "JavaScript Libraries",
        "name": "HTMX",
        "patterns": [
            {"script_src": re.compile(r"htmx(?:\.min)?\.js", re.I)},
            {"html": re.compile(r"hx-get=|hx-post=|hx-target=", re.I)},
        ],
    },
    {
        "category": "JavaScript Libraries",
        "name": "Alpine.js",
        "patterns": [
            {"script_src": re.compile(r"alpinejs|alpine\.js", re.I)},
            {"html": re.compile(r"x-data=|x-bind=|x-on:", re.I)},
        ],
    },

    # ── CSS Frameworks ───────────────────────────────────────────────────────
    {
        "category": "CSS Frameworks",
        "name": "Bootstrap",
        "patterns": [
            {"link_href": re.compile(r"bootstrap[.-]([\d.]+)(?:\.min)?\.css", re.I)},
            {"script_src": re.compile(r"bootstrap[.-]([\d.]+)(?:\.min)?\.js", re.I)},
            {"html": re.compile(r"bootstrap[.-]([\d.]+)(?:\.min)?\.css", re.I)},
        ],
    },
    {
        "category": "CSS Frameworks",
        "name": "Tailwind CSS",
        "patterns": [
            {"link_href": re.compile(r"tailwind(?:css)?", re.I)},
            {"html": re.compile(r"cdn\.tailwindcss\.com|tailwindcss", re.I)},
        ],
    },
    {
        "category": "CSS Frameworks",
        "name": "Foundation",
        "patterns": [
            {"link_href": re.compile(r"foundation\.min\.css|foundation\.css", re.I)},
        ],
    },
    {
        "category": "CSS Frameworks",
        "name": "Bulma",
        "patterns": [
            {"link_href": re.compile(r"bulma(?:\.min)?\.css", re.I)},
        ],
    },
    {
        "category": "CSS Frameworks",
        "name": "Materialize",
        "patterns": [
            {"link_href": re.compile(r"materialize(?:\.min)?\.css", re.I)},
        ],
    },

    # ── CDNs ─────────────────────────────────────────────────────────────────
    {
        "category": "CDN",
        "name": "Cloudflare",
        "patterns": [
            {"header": ("CF-Ray", None)},
            {"header": ("Server", re.compile(r"cloudflare", re.I))},
        ],
    },
    {
        "category": "CDN",
        "name": "Amazon CloudFront",
        "patterns": [
            {"header": ("X-Amz-Cf-Id", None)},
            {"header": ("Via", re.compile(r"CloudFront", re.I))},
        ],
    },
    {
        "category": "CDN",
        "name": "Fastly",
        "patterns": [
            {"header": ("X-Fastly-Request-ID", None)},
            {"header": ("X-Served-By", re.compile(r"cache-", re.I))},
        ],
    },
    {
        "category": "CDN",
        "name": "Akamai",
        "patterns": [
            {"header": ("X-Akamai-Transformed", None)},
            {"header": ("Server", re.compile(r"AkamaiGHost", re.I))},
        ],
    },
    {
        "category": "CDN",
        "name": "Vercel",
        "patterns": [
            {"header": ("X-Vercel-Id", None)},
            {"header": ("Server", re.compile(r"Vercel", re.I))},
        ],
    },
    {
        "category": "CDN",
        "name": "Netlify",
        "patterns": [
            {"header": ("X-Nf-Request-Id", None)},
            {"header": ("Server", re.compile(r"Netlify", re.I))},
        ],
    },

    # ── Analytics / Tag Managers ─────────────────────────────────────────────
    {
        "category": "Analytics",
        "name": "Google Analytics",
        "patterns": [
            {"html": re.compile(r"google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+", re.I)},
            {"script_src": re.compile(r"google-analytics\.com|googletagmanager\.com/gtag", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Google Tag Manager",
        "patterns": [
            {"html": re.compile(r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+", re.I)},
            {"script_src": re.compile(r"googletagmanager\.com/gtm", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Matomo",
        "patterns": [
            {"html": re.compile(r"matomo\.php|piwik\.php|matomo\.js", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Plausible",
        "patterns": [
            {"script_src": re.compile(r"plausible\.io/js", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Hotjar",
        "patterns": [
            {"html": re.compile(r"hotjar\.com|hjid:", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Segment",
        "patterns": [
            {"html": re.compile(r"segment\.com/analytics\.js|analytics\.load", re.I)},
        ],
    },
    {
        "category": "Analytics",
        "name": "Mixpanel",
        "patterns": [
            {"html": re.compile(r"cdn\.mxpnl\.com|mixpanel\.com", re.I)},
        ],
    },

    # ── Security / WAF ───────────────────────────────────────────────────────
    {
        "category": "Security",
        "name": "Cloudflare WAF",
        "patterns": [
            {"html": re.compile(r"__cf_chl_|Cloudflare Ray ID|cf-browser-verification", re.I)},
        ],
    },
    {
        "category": "Security",
        "name": "reCAPTCHA",
        "patterns": [
            {"html": re.compile(r"google\.com/recaptcha|grecaptcha\.", re.I)},
            {"script_src": re.compile(r"google\.com/recaptcha", re.I)},
        ],
    },
    {
        "category": "Security",
        "name": "hCaptcha",
        "patterns": [
            {"html": re.compile(r"hcaptcha\.com", re.I)},
            {"script_src": re.compile(r"hcaptcha\.com", re.I)},
        ],
    },
    {
        "category": "Security",
        "name": "Imperva Incapsula",
        "patterns": [
            {"header": ("X-Iinfo", None)},
            {"header": ("X-CDN", re.compile(r"Incapsula", re.I))},
        ],
    },

    # ── E-Commerce ───────────────────────────────────────────────────────────
    {
        "category": "E-Commerce",
        "name": "WooCommerce",
        "patterns": [
            {"html": re.compile(r"woocommerce|wc-ajax=", re.I)},
            {"link_href": re.compile(r"woocommerce", re.I)},
        ],
    },
    {
        "category": "E-Commerce",
        "name": "Magento",
        "patterns": [
            {"html": re.compile(r"Mage\.Cookies|mage/cookies|var BLANK_URL|Magento", re.I)},
            {"cookie": "frontend"},
        ],
    },
    {
        "category": "E-Commerce",
        "name": "PrestaShop",
        "patterns": [
            {"html": re.compile(r"prestashop|presta_shop", re.I)},
            {"cookie": "PrestaShop"},
        ],
    },
    {
        "category": "E-Commerce",
        "name": "BigCommerce",
        "patterns": [
            {"html": re.compile(r"bigcommerce\.com|cdn11\.bigcommerce\.com", re.I)},
        ],
    },

    # ── Infrastructure / Hosting ─────────────────────────────────────────────
    {
        "category": "PaaS / Hosting",
        "name": "Heroku",
        "patterns": [
            {"header": ("Via", re.compile(r"vegur", re.I))},
            {"header": ("Server", re.compile(r"Cowboy", re.I))},
        ],
    },
    {
        "category": "PaaS / Hosting",
        "name": "GitHub Pages",
        "patterns": [
            {"header": ("Server", re.compile(r"GitHub\.com", re.I))},
            {"header": ("X-GitHub-Request-Id", None)},
        ],
    },
    {
        "category": "PaaS / Hosting",
        "name": "AWS S3",
        "patterns": [
            {"header": ("Server", re.compile(r"AmazonS3", re.I))},
            {"header": ("X-Amz-Request-Id", None)},
        ],
    },

    # ── Font Services ─────────────────────────────────────────────────────────
    {
        "category": "Font Services",
        "name": "Google Fonts",
        "patterns": [
            {"link_href": re.compile(r"fonts\.googleapis\.com", re.I)},
            {"html": re.compile(r"fonts\.googleapis\.com", re.I)},
        ],
    },
    {
        "category": "Font Services",
        "name": "Adobe Fonts (Typekit)",
        "patterns": [
            {"html": re.compile(r"use\.typekit\.net|adobe\.fonts", re.I)},
        ],
    },

    # ── Miscellaneous ─────────────────────────────────────────────────────────
    {
        "category": "Miscellaneous",
        "name": "Intercom",
        "patterns": [
            {"html": re.compile(r"intercom\.io|intercomSettings", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "Zendesk",
        "patterns": [
            {"html": re.compile(r"zendesk\.com|zESettings", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "HubSpot",
        "patterns": [
            {"html": re.compile(r"js\.hs-scripts\.com|hubspot\.com/hs\.js|hs-analytics", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "Stripe",
        "patterns": [
            {"script_src": re.compile(r"js\.stripe\.com", re.I)},
            {"html": re.compile(r"js\.stripe\.com", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "Sentry",
        "patterns": [
            {"script_src": re.compile(r"browser\.sentry-cdn\.com|sentry\.io", re.I)},
            {"html": re.compile(r"Sentry\.init\(|sentry\.io", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "Webpack",
        "patterns": [
            {"html": re.compile(r"webpackJsonp|__webpack_require__|webpack\.js", re.I)},
        ],
    },
    {
        "category": "Miscellaneous",
        "name": "Vite",
        "patterns": [
            {"html": re.compile(r"/@vite/client|vite\.config\.|__vite_plugin", re.I)},
            {"script_src": re.compile(r"/@vite/|/vite\.", re.I)},
        ],
    },
]

# ---------------------------------------------------------------------------
# Deduplication — Angular/AngularJS can both match; prefer Angular if ng-version found
# ---------------------------------------------------------------------------
_MUTEX_GROUPS = [
    {"AngularJS", "Angular"},  # if ng-version= present → Angular; else AngularJS
]


def _fetch_page(domain: str):
    """
    Fetch the target homepage, trying HTTPS then HTTP.
    Uses verify=True (system CA bundle) first. If the target has an invalid
    or self-signed certificate, falls back to verify=False so technology
    detection still works — the cert state is already reported by
    certificates.py; this module's job is to read page content.
    Returns (response, html).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CoreRecon/3.0)"},
                verify=True,   # system CA bundle — validates our outbound TLS
            )
            return resp, resp.text

        except requests.exceptions.SSLError:
            # Target has a bad/self-signed cert. Fall back to unverified so
            # we can still fingerprint its technology stack.
            log.warning(
                "SSL verification failed — falling back to unverified fetch for tech detection",
                extra={"url": url},
            )
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; CoreRecon/3.0)"},
                    verify=False,
                )
                urllib3.warnings.resetwarnings()
                return resp, resp.text
            except Exception as exc:
                log.warning(f"Unverified fetch also failed ({scheme}): {exc}")

        except Exception as exc:
            log.warning(f"Fetch failed ({scheme}): {exc}")

    return None, ""


def _extract_version_from_pattern(pattern: re.Pattern, text: str) -> Optional[str]:
    """Run a regex and return the first capture group as version if present."""
    if pattern is None:
        return None
    m = pattern.search(text)
    if not m:
        return None
    try:
        ver = m.group(1)
        return ver.strip() if ver else None
    except IndexError:
        return None


def _check_rule(rule: Dict, headers: Dict[str, str], html: str, cookies: Dict[str, str]) -> Optional[str]:
    """
    Run all patterns for a rule. Returns version string (or "" if matched but no version),
    or None if not matched.
    """
    for pat in rule["patterns"]:
        version = None

        if "header" in pat:
            hdr_name, hdr_regex = pat["header"]
            hdr_val = headers.get(hdr_name.lower(), "")
            if not hdr_val:
                continue
            if hdr_regex is None:
                return ""  # presence-only match
            ver = _extract_version_from_pattern(hdr_regex, hdr_val)
            if hdr_regex.search(hdr_val):
                return ver or ""

        elif "meta" in pat:
            ver = _extract_version_from_pattern(pat["meta"], html)
            if pat["meta"].search(html):
                return ver or ""

        elif "html" in pat:
            ver = _extract_version_from_pattern(pat["html"], html)
            if pat["html"].search(html):
                return ver or ""

        elif "cookie" in pat:
            if pat["cookie"].lower() in [c.lower() for c in cookies]:
                return ""

        elif "script_src" in pat:
            # Extract all <script src="..."> values and test each
            for src_match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                src = src_match.group(1)
                ver = _extract_version_from_pattern(pat["script_src"], src)
                if pat["script_src"].search(src):
                    return ver or ""

        elif "link_href" in pat:
            for href_match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
                href = href_match.group(1)
                ver = _extract_version_from_pattern(pat["link_href"], href)
                if pat["link_href"].search(href):
                    return ver or ""

    return None


def _deduplicate(detections: List[Dict]) -> List[Dict]:
    """Remove lower-priority duplicates within mutex groups."""
    detected_names = {d["name"] for d in detections}
    filtered = []
    for det in detections:
        skip = False
        for group in _MUTEX_GROUPS:
            if det["name"] in group:
                # Keep this only if it's the highest-priority member detected
                others = group - {det["name"]}
                # Simple rule: if Angular is detected, drop AngularJS
                if "Angular" in detected_names and det["name"] == "AngularJS":
                    skip = True
                    break
        if not skip:
            filtered.append(det)
    return filtered


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def get_technology_stack(domain: str) -> Dict[str, Any]:
    """
    Fingerprint the technology stack of a domain using HTTP header and
    HTML pattern matching.

    Returns dict: {category: [{name, version, eol_risk, eol_note}]}
    Compatible with the existing v2.x output structure consumed by
    the risk engine, correlations, and frontend.
    """
    resp, html = _fetch_page(domain)

    if resp is None:
        log.warning("Technology detection: could not fetch page", extra={"domain": domain})
        return {"error": "Could not fetch page for technology analysis"}

    # Normalize headers to lowercase keys for consistent lookup
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = {c.name: c.value for c in resp.cookies}

    detections: List[Dict] = []
    seen_names: set = set()

    for rule in TECH_RULES:
        name = rule["name"]
        if name in seen_names:
            continue

        version = _check_rule(rule, headers, html, cookies)
        if version is not None:
            seen_names.add(name)
            eol = _check_eol(name, version)
            detections.append({
                "category": rule["category"],
                "name": name,
                "version": version if version is not None else "",
                "eol_risk": eol["eol_risk"],
                "eol_note": eol["eol_note"],
            })

    detections = _deduplicate(detections)

    # Group by category — matches existing output structure
    categorized: Dict[str, List] = {}
    for det in detections:
        cat = det["category"]
        if cat not in categorized:
            categorized[cat] = []
        categorized[cat].append({
            "name": det["name"],
            "version": det["version"],
            "eol_risk": det["eol_risk"],
            "eol_note": det["eol_note"],
        })

    result = dict(sorted(categorized.items()))

    total = sum(len(v) for v in result.values())
    log.info(
        "Technology stack analyzed",
        extra={
            "domain": domain,
            "categories": len(result),
            "technologies": total,
        },
    )

    # Return a useful message if nothing detected rather than empty dict
    if not result:
        return {"note": "No technology signatures identified — site may use heavy obfuscation or serve minimal HTML"}

    return result
