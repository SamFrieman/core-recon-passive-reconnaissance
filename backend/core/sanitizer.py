"""
CoreRecon Input Sanitizer v1.0
Central validation and sanitization for all user-supplied input.

Layered defence:
  Layer 1 — Structural checks   : length, encoding, null bytes
  Layer 2 — Allowlist            : only characters valid in a domain/IP/URL
  Layer 3 — SQL injection        : keyword + pattern blocklist (very tight)
  Layer 4 — Command injection    : shell metacharacters and operator sequences
  Layer 5 — XSS / HTML injection : tags, event handlers, javascript: URIs
  Layer 6 — Path traversal       : ../ sequences and encoded equivalents
  Layer 7 — Referential removal  : strips embedded URLs, protocol refs,
                                   encoded payloads (%xx, \\uXXXX, &#xx;)
  Layer 8 — Final structural     : must still look like a valid FQDN / IP / URL
                                   after all stripping

Usage:
    from backend.core.sanitizer import sanitize_target, SanitizationError

    try:
        clean = sanitize_target(raw_input)
    except SanitizationError as e:
        # return 400 with e.reason — never expose e.detail to the client
        raise HTTPException(status_code=400, detail=e.reason)
"""

import re
import urllib.parse
from typing import Optional

from backend.core.logger import get_logger

log = get_logger("corerecon.sanitizer")


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class SanitizationError(Exception):
    """
    Raised when input fails any sanitization layer.
    `reason`  — safe string suitable for returning to the client (generic)
    `detail`  — full internal description for logging only (never sent to client)
    """
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


# ---------------------------------------------------------------------------
# Layer 3 — SQL injection patterns
# Extremely tight. A domain name legitimately contains only [a-z0-9.\-],
# so SQL keywords should NEVER appear. We block them absolutely.
# ---------------------------------------------------------------------------

# Full-word SQL keywords (word-boundary matched)
_SQL_KEYWORDS = re.compile(
    r"""
    \b(?:
        SELECT   | INSERT   | UPDATE   | DELETE   | DROP     |
        CREATE   | ALTER    | TRUNCATE | REPLACE  | MERGE    |
        EXEC     | EXECUTE  | CALL     | DECLARE  | SET      |
        UNION    | INTERSECT| EXCEPT   | FROM     | WHERE    |
        HAVING   | ORDER    | GROUP    | LIMIT    | OFFSET   |
        JOIN     | INNER    | OUTER    | LEFT     | RIGHT    |
        CROSS    | NATURAL  | ON       | USING    | AS       |
        INTO     | VALUES   | TABLE    | DATABASE | SCHEMA   |
        INDEX    | VIEW     | TRIGGER  | FUNCTION | PROCEDURE|
        GRANT    | REVOKE   | COMMIT   | ROLLBACK | SAVEPOINT|
        TRANSACTION         | BEGIN    | END      |
        CAST     | CONVERT  | COALESCE | NULLIF   | ISNULL   |
        CONCAT   | SUBSTRING| SUBSTR   | TRIM     | UPPER    |
        LOWER    | LENGTH   | REPLACE  | CHARINDEX| INSTR    |
        SLEEP    | BENCHMARK| WAITFOR  | DELAY    | PG_SLEEP |
        LOAD_FILE| OUTFILE  | DUMPFILE | INFORMATION_SCHEMA   |
        SYSOBJECTS          | SYSCOLUMNS
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# SQL syntax tokens — standalone symbols / sequences with no domain use
_SQL_SYNTAX = re.compile(
    r"""
    (?:
        --          |   # SQL line comment
        /\*         |   # SQL block comment open
        \*/         |   # SQL block comment close
        ;\s*\w      |   # statement terminator followed by word (stacked queries)
        '\s*OR\s*'  |   # classic ' OR ' injection
        '\s*AND\s*' |   # classic ' AND ' injection
        =\s*'       |   # = ' pattern
        '\s*=       |   # ' = pattern
        \bOR\b\s+\d |   # OR 1
        \bAND\b\s+\d|   # AND 1
        \bOR\b\s+'\w|   # OR 'a
        0x[0-9a-f]+ |   # hex literals
        \|\|        |   # string concat operator (Oracle/Postgres)
        @@\w+           # SQL Server global variables
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Layer 4 — Command injection / shell operators
# ---------------------------------------------------------------------------

_CMD_PATTERNS = re.compile(
    r"""
    (?:
        [;&|`$]         |   # shell operators
        \$\(            |   # command substitution $(
        `[^`]*`         |   # backtick execution
        \|\s*\w         |   # pipe to command
        &&              |   # shell AND
        \|\|            |   # shell OR (also caught by SQL layer)
        >\s*/           |   # redirect to path
        <\s*/           |   # redirect from path
        \.\./           |   # path traversal (forward)
        \.\.\\          |   # path traversal (backslash)
        /etc/           |   # common Linux path
        /proc/          |   # proc filesystem
        /bin/           |   # binaries
        cmd\.exe        |   # Windows shell
        powershell      |   # PowerShell
        /bin/sh         |   # sh
        /bin/bash       |   # bash
        wget\s          |   # wget download
        curl\s          |   # curl download
        python\s        |   # python execution
        perl\s          |   # perl execution
        ruby\s          |   # ruby execution
        nc\s            |   # netcat
        ncat\s              # ncat
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Layer 5 — XSS / HTML injection
# ---------------------------------------------------------------------------

_XSS_PATTERNS = re.compile(
    r"""
    (?:
        <[a-z]          |   # any HTML/XML tag open
        </[a-z]         |   # any closing tag
        javascript\s*:  |   # javascript: URI
        vbscript\s*:    |   # vbscript: URI
        data\s*:        |   # data: URI (can carry payloads)
        on\w+\s*=       |   # event handlers (onclick=, onload=, etc.)
        expression\s*\( |   # CSS expression()
        <\s*script      |   # script tag (with optional spaces)
        <\s*iframe      |   # iframe
        <\s*object      |   # object tag
        <\s*embed       |   # embed tag
        <\s*svg         |   # SVG (can contain scripts)
        <\s*img         |   # img (onerror= attacks)
        <\s*link        |   # link (imports)
        <\s*meta            # meta refresh / redirect
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Layer 6 — Path traversal
# ---------------------------------------------------------------------------

_TRAVERSAL_PATTERNS = re.compile(
    r"""
    (?:
        \.\.[\\/]       |   # ../  or ..\
        %2e%2e          |   # URL-encoded ..
        %252e           |   # double-encoded .
        \.\.%2f         |   # mixed encoding
        \.\.%5c             # mixed encoding backslash
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Layer 7 — Referential removal
# Strips embedded protocol references, encoded payloads, and unicode escapes
# that could smuggle content past earlier layers.
# ---------------------------------------------------------------------------

# Protocols that should never appear inside a domain/IP target
_EMBEDDED_PROTO = re.compile(
    r"""
    (?:
        ftp://      |
        file://     |
        ldap://     |
        dict://     |
        gopher://   |
        tftp://     |
        ssh://      |
        telnet://   |
        smtp://     |
        irc://
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# HTML entity references: &#60; &#x3c; &lt; etc.
_HTML_ENTITIES = re.compile(r"&#?\w+;", re.IGNORECASE)

# Unicode escapes: \u0041, \U00000041, \x41
_UNICODE_ESCAPES = re.compile(r"\\[uUx][0-9a-fA-F]{2,8}")

# URL percent-encoding sequences beyond what's valid in a URL path
# We allow %20 (space) but strip anything that decodes to a control char
_SUSPICIOUS_ENCODING = re.compile(r"%[0-9a-fA-F]{2}")


def _strip_referential(value: str) -> str:
    """
    Remove embedded references and encoded payloads that could smuggle
    content past structural checks. Returns cleaned string.
    """
    # Remove HTML entities
    value = _HTML_ENTITIES.sub("", value)
    # Remove unicode escape sequences
    value = _UNICODE_ESCAPES.sub("", value)
    # Decode percent-encoding once and remove any non-printable results
    try:
        decoded = urllib.parse.unquote(value, errors="strict")
        # If decoding changed the string, re-run entity/escape removal
        if decoded != value:
            decoded = _HTML_ENTITIES.sub("", decoded)
            decoded = _UNICODE_ESCAPES.sub("", decoded)
            value = decoded
    except Exception:
        pass  # Malformed encoding — leave as-is; later layers will catch it

    return value


# ---------------------------------------------------------------------------
# Layer 8 — Final domain/IP/URL allowlist
# After all stripping, the value must consist only of characters that are
# valid in a domain label, IPv4/IPv6 address, or a minimal URL.
# Allowlist: [a-z0-9], hyphen, dot, colon (port/IPv6), brackets (IPv6),
#            slash and @ (URL path/userinfo), http(s):// prefix only.
# ---------------------------------------------------------------------------

_ALLOWED_CHARS = re.compile(r"^[a-zA-Z0-9.\-:/\[\]@%_~]+$")

# http:// or https:// prefix — allowed as a URL prefix only
_HTTP_PREFIX = re.compile(r"^https?://", re.IGNORECASE)

# A domain label must not be all hyphens or start/end with a hyphen
_LABEL_HYPHENS = re.compile(r"(?:^-|-$|^-+$)", re.MULTILINE)

# IP address pattern for quick structural check
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_BRACKET = re.compile(r"^\[[\da-fA-F:]+\]$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sanitize_target(raw: str) -> str:
    """
    Run all sanitization layers against a raw user-supplied target string.

    Returns the cleaned, validated string ready for normalization.
    Raises SanitizationError with a safe client-facing reason on any failure.

    This function NEVER raises generic Python exceptions — callers can rely
    on SanitizationError being the only error path.
    """
    if not isinstance(raw, str):
        raise SanitizationError("Invalid input type", f"Expected str, got {type(raw)}")

    # --- Layer 1: Structural ---
    if not raw or not raw.strip():
        raise SanitizationError("Target cannot be empty")

    value = raw.strip()

    # Null bytes
    if "\x00" in value or "%00" in value.lower():
        raise SanitizationError(
            "Invalid input",
            f"Null byte detected in input: {value!r}"
        )

    # Length cap — 253 is the maximum valid FQDN length per RFC 1035
    if len(value) > 253:
        raise SanitizationError(
            "Target too long (max 253 characters)",
            f"Input length {len(value)} exceeds 253"
        )

    # Control characters (excluding whitespace already stripped)
    if re.search(r"[\x01-\x1f\x7f]", value):
        raise SanitizationError(
            "Invalid input",
            f"Control characters detected in input: {value!r}"
        )

    # --- Layer 7: Referential removal (run early so decoded form is checked) ---
    value = _strip_referential(value)

    # Re-check length after referential removal (encoding can expand)
    if len(value) > 253:
        raise SanitizationError(
            "Target too long after decoding",
            f"Post-decode length {len(value)} exceeds 253"
        )

    # Block embedded non-http protocols outright
    if _EMBEDDED_PROTO.search(value):
        raise SanitizationError(
            "Invalid input",
            f"Embedded non-HTTP protocol in input: {value!r}"
        )

    # --- Layer 3: SQL injection ---
    if _SQL_KEYWORDS.search(value):
        log.warning("SQL keyword detected in input", extra={"input": value[:60]})
        raise SanitizationError(
            "Invalid input",
            f"SQL keyword pattern in input: {value!r}"
        )

    if _SQL_SYNTAX.search(value):
        log.warning("SQL syntax pattern detected in input", extra={"input": value[:60]})
        raise SanitizationError(
            "Invalid input",
            f"SQL syntax pattern in input: {value!r}"
        )

    # --- Layer 4: Command injection ---
    if _CMD_PATTERNS.search(value):
        log.warning("Command injection pattern detected", extra={"input": value[:60]})
        raise SanitizationError(
            "Invalid input",
            f"Command injection pattern in input: {value!r}"
        )

    # --- Layer 5: XSS / HTML ---
    if _XSS_PATTERNS.search(value):
        log.warning("XSS pattern detected in input", extra={"input": value[:60]})
        raise SanitizationError(
            "Invalid input",
            f"XSS pattern in input: {value!r}"
        )

    # --- Layer 6: Path traversal ---
    if _TRAVERSAL_PATTERNS.search(value):
        log.warning("Path traversal detected in input", extra={"input": value[:60]})
        raise SanitizationError(
            "Invalid input",
            f"Path traversal pattern in input: {value!r}"
        )

    # --- Layer 2: Allowlist (after stripping http prefix for URL inputs) ---
    # Strip an http(s):// prefix temporarily for the allowlist check
    check_value = _HTTP_PREFIX.sub("", value)

    if not _ALLOWED_CHARS.match(check_value):
        # Find the offending character(s) for the internal log
        bad_chars = set(re.findall(r"[^a-zA-Z0-9.\-:/\[\]@%_~]", check_value))
        log.warning(
            "Disallowed characters in input",
            extra={"input": value[:60], "bad_chars": list(bad_chars)},
        )
        raise SanitizationError(
            "Invalid characters in target",
            f"Disallowed chars {bad_chars!r} in input: {value!r}"
        )

    # --- Layer 8: Post-strip structural check ---
    # Must have at least one dot (domain) OR be a bare IP OR be bracketed IPv6
    # Single-label hostnames (intranet) are allowed but must be purely alphanum+hyphen
    if not (
        "." in check_value
        or _IPV4.match(check_value)
        or _IPV6_BRACKET.match(check_value)
        or re.match(r"^[a-zA-Z0-9\-]+$", check_value)   # single-label intranet host
    ):
        raise SanitizationError(
            "Invalid target format",
            f"Input does not resolve to a valid domain/IP structure: {value!r}"
        )

    log.info("Input passed sanitization", extra={"input": value[:60]})
    return value


def sanitize_db_param(value: str, max_length: int = 253) -> str:
    """
    Lightweight sanitizer for values used as database query parameters.
    Used as a secondary defence — the primary defence is always parameterised queries.

    Strips all characters except those valid in a domain/IP label.
    Raises SanitizationError if the result would be empty or too long.
    """
    if not isinstance(value, str) or not value.strip():
        raise SanitizationError("Invalid parameter", "Empty or non-string DB param")

    cleaned = re.sub(r"[^a-zA-Z0-9.\-]", "", value.strip())

    if not cleaned:
        raise SanitizationError(
            "Invalid parameter",
            f"DB param sanitization removed all content from: {value!r}"
        )

    if len(cleaned) > max_length:
        raise SanitizationError(
            "Parameter too long",
            f"DB param length {len(cleaned)} > {max_length}"
        )

    return cleaned
