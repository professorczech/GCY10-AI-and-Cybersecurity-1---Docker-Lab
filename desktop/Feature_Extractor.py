import base64
import json
import re
import ipaddress
import shutil
import subprocess
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from math import log2
from urllib.parse import urlsplit

# ------------------------------------------------------------
# INPUT (Shuffle-safe): Inject ONLY the base64 string
# Use the + button and insert: $exec.data.eml_b64
# ------------------------------------------------------------
EML_B64 = r'''{{ $exec.data.eml_b64 }}'''

# Optional: If you ever switch to plain text injection later
EML_TEXT = r'''{{ $exec.data.eml_text }}'''

# Toggle DNS lookups (TXT records for SPF / DKIM key presence)
ENABLE_DNS_LOOKUPS = False

SUSPICIOUS_TLDS = set([
    "zip", "mov", "top", "xyz", "loan", "click", "support", "icu", "shop", "live", "fit"
])

URL_SHORTENERS = set([
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
])

PHISH_PHRASES = [
    "verify your account", "account suspended", "password reset", "confirm your password",
    "unusual activity", "urgent", "immediately", "last warning", "click here",
    "sign in", "invoice", "wire transfer", "payment failed", "security alert",
    "update your billing", "locked", "restricted", "validate", "authenticate"
]

SUSPICIOUS_ATTACHMENT_EXTS = set([
    "exe", "js", "vbs", "vbe", "scr", "bat", "cmd", "ps1", "hta",
    "iso", "img", "lnk", "zip", "rar", "7z", "html"
])

# ----------------------------
# Helpers
# ----------------------------

def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * log2(p)
    return ent

def strip_html(s):
    s = re.sub(r"<script[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<style[\s\S]*?</style>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def extract_body_parts(msg):
    plain_parts = []
    html_parts_stripped = []
    html_parts_raw = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                content = part.get_content()
                if not content:
                    continue
                if ctype == "text/plain":
                    plain_parts.append(content)
                else:
                    html_parts_raw.append(content)
                    html_parts_stripped.append(strip_html(content))
            except Exception:
                pass
    else:
        try:
            ctype = (msg.get_content_type() or "").lower()
            content = msg.get_content()
            if content:
                if ctype == "text/html":
                    html_parts_raw.append(content)
                    html_parts_stripped.append(strip_html(content))
                else:
                    plain_parts.append(content)
        except Exception:
            pass

    plain_text = "\n".join([p for p in plain_parts if p])
    html_text_stripped = "\n".join([p for p in html_parts_stripped if p])
    html_raw = "\n".join([p for p in html_parts_raw if p])
    return plain_text, html_text_stripped, html_raw

def get_first_address_domain(header_value):
    addrs = getaddresses([header_value or ""])
    if not addrs:
        return None, None
    _name, email_addr = addrs[0]
    email_addr = (email_addr or "").strip()
    if "@" in email_addr:
        domain = email_addr.split("@", 1)[1].lower()
        return email_addr, domain
    return (email_addr or None), None

def parse_auth_results(authres):
    out = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not authres:
        return out

    m_spf = re.search(r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", authres, flags=re.I)
    if m_spf:
        out["spf"] = m_spf.group(1).lower()

    m_dkim = re.search(r"\bdkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)\b", authres, flags=re.I)
    if m_dkim:
        out["dkim"] = m_dkim.group(1).lower()

    m_dmarc = re.search(r"\bdmarc\s*=\s*(pass|fail|bestguesspass|none)\b", authres, flags=re.I)
    if m_dmarc:
        out["dmarc"] = m_dmarc.group(1).lower()

    return out

def parse_received_spf(received_spf):
    if not received_spf:
        return "unknown"
    m = re.search(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b", received_spf.strip(), flags=re.I)
    return m.group(1).lower() if m else "unknown"

def looks_like_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def extract_urls(text, html_raw):
    urls = set()

    if text:
        for u in re.findall(r"https?://[^\s\"'<>]+", text, flags=re.I):
            urls.add(u)

    if html_raw:
        for u in re.findall(r'href\s*=\s*["\'](https?://[^"\']+)["\']', html_raw, flags=re.I):
            urls.add(u)
        for u in re.findall(r'src\s*=\s*["\'](https?://[^"\']+)["\']', html_raw, flags=re.I):
            urls.add(u)

    cleaned = []
    for u in sorted(urls):
        u2 = u.split("#", 1)[0].strip()
        cleaned.append(u2)
    return cleaned

def dns_txt_lookup(name):
    # dnspython if present
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(name, "TXT")
        out = []
        for r in answers:
            chunks = []
            for s in getattr(r, "strings", []):
                try:
                    chunks.append(s.decode("utf-8", "replace"))
                except Exception:
                    chunks.append(str(s))
            if chunks:
                out.append("".join(chunks))
            else:
                out.append(str(r))
        return out
    except Exception:
        pass

    # dig
    if shutil.which("dig"):
        try:
            p = subprocess.run(["dig", "+short", "TXT", name], capture_output=True, text=True, timeout=2)
            lines = [ln.strip().strip('"') for ln in (p.stdout or "").splitlines() if ln.strip()]
            return lines or None
        except Exception:
            return None

    # nslookup
    if shutil.which("nslookup"):
        try:
            p = subprocess.run(["nslookup", "-type=TXT", name], capture_output=True, text=True, timeout=2)
            out = []
            for ln in (p.stdout or "").splitlines():
                if "text =" in ln.lower():
                    out.append(ln.split("=", 1)[-1].strip().strip('"'))
            return out or None
        except Exception:
            return None

    return None

def get_spf_record(domain):
    txts = dns_txt_lookup(domain) or []
    for t in txts:
        if "v=spf1" in t.lower():
            return t
    return None

def get_dkim_key(selector, dkim_domain):
    name = (selector + "._domainkey." + dkim_domain).strip(".")
    txts = dns_txt_lookup(name) or []
    return txts[0] if txts else None

# ----------------------------
# Main
# ----------------------------

b64 = (EML_B64 or "").strip()
eml_text = (EML_TEXT or "").strip()

if (not b64 or b64 == "null") and (not eml_text or eml_text == "null"):
    print(json.dumps({
        "success": False,
        "error": "No email content injected. Expected $" + "exec.data.eml_b64 (preferred) or $" + "exec.data.eml_text."
    }))
    raise SystemExit(0)

eml_bytes = b""
if b64 and b64 != "null":
    try:
        eml_bytes = base64.b64decode(b64)
    except Exception as e:
        print(json.dumps({"success": False, "error": "Base64 decode failed: {0}".format(e)}))
        raise SystemExit(0)
else:
    eml_bytes = eml_text.encode("utf-8", errors="replace")

msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)

# Basic headers
subject = msg.get("subject", "") or ""
from_h = msg.get("from", "") or ""
reply_to = msg.get("reply-to", "") or ""
return_path = msg.get("return-path", "") or ""
message_id = msg.get("message-id", "") or ""
date_h = msg.get("date", "") or ""

from_addr, from_domain = get_first_address_domain(from_h)
reply_addr, reply_domain = get_first_address_domain(reply_to)
rp_addr, rp_domain = get_first_address_domain(return_path)

reply_to_mismatch = bool(reply_domain and from_domain and (reply_domain != from_domain))
return_path_mismatch = bool(rp_domain and from_domain and (rp_domain != from_domain))

# Auth parsing
authres = msg.get("Authentication-Results", "") or ""
recv_spf = msg.get("Received-SPF", "") or ""
auth_parsed = parse_auth_results(authres)

spf_result = auth_parsed.get("spf", "unknown")
if spf_result == "unknown":
    spf_result = parse_received_spf(recv_spf)

dkim_result = auth_parsed.get("dkim", "unknown")
dmarc_result = auth_parsed.get("dmarc", "unknown")

# DKIM selector/domain (for optional DNS)
dkim_sig = msg.get("DKIM-Signature", "") or ""
dkim_selector = None
dkim_domain = None
if dkim_sig:
    m_s = re.search(r"\bs\s*=\s*([^; \t]+)", dkim_sig)
    m_d = re.search(r"\bd\s*=\s*([^; \t]+)", dkim_sig)
    if m_s:
        dkim_selector = m_s.group(1).strip()
    if m_d:
        dkim_domain = m_d.group(1).strip().lower()

# Body extraction
plain_text, html_text_stripped, html_raw = extract_body_parts(msg)
full_text = "\n".join([t for t in [plain_text, html_text_stripped] if t]).strip()
full_text_l = (full_text or "").lower()

has_html = bool(html_raw.strip())
has_form = bool(re.search(r"<form\b", html_raw, flags=re.I)) if html_raw else False
has_password_field = bool(re.search(r'type\s*=\s*["\']password["\']', html_raw, flags=re.I)) if html_raw else False

# Attachments
attachments = []
has_suspicious_attachment = False

if msg.is_multipart():
    for part in msg.walk():
        disp = (part.get("Content-Disposition", "") or "").lower()
        filename = part.get_filename()
        if not filename and "attachment" not in disp:
            continue
        filename = filename or ""
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        ctype = (part.get_content_type() or "").lower()
        attachments.append({"filename": filename, "ext": ext, "content_type": ctype})
        if ext in SUSPICIOUS_ATTACHMENT_EXTS:
            has_suspicious_attachment = True

# URL features
urls = extract_urls(full_text, html_raw)
domains = []
url_features = []
pathq_entropies = []

suspicious_flags = {
    "any_ip_host": False,
    "any_punycode": False,
    "any_shortener": False,
    "any_suspicious_tld": False,
    "any_non_ascii_domain": False,
    "any_at_in_url": False
}

for u in urls:
    clean = u.split("#", 1)[0]
    parts = urlsplit(clean)
    host = (parts.hostname or "").strip().lower()
    domain = host
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

    path_q = (parts.path or "") + ("?" + parts.query if parts.query else "")
    e_pq = shannon_entropy(path_q)
    pathq_entropies.append(e_pq)

    if looks_like_ip(domain):
        suspicious_flags["any_ip_host"] = True
    if domain.startswith("xn--") or ".xn--" in domain:
        suspicious_flags["any_punycode"] = True
    if domain in URL_SHORTENERS:
        suspicious_flags["any_shortener"] = True
    if tld in SUSPICIOUS_TLDS:
        suspicious_flags["any_suspicious_tld"] = True
    if any(ord(ch) > 127 for ch in domain):
        suspicious_flags["any_non_ascii_domain"] = True
    if "@" in clean:
        suspicious_flags["any_at_in_url"] = True

    domains.append(domain)

    url_features.append({
        "url": clean,
        "domain": domain,
        "tld": tld,
        "has_query": bool(parts.query),
        "entropy_url": round(shannon_entropy(clean), 4),
        "entropy_domain": round(shannon_entropy(domain), 4),
        "entropy_path_query": round(e_pq, 4)
    })

unique_domains = sorted(set([d for d in domains if d]))
unique_domain_count = len(unique_domains)

if not pathq_entropies:
    pathq_entropies = [0.0]

url_entropy_mean = sum(pathq_entropies) / float(len(pathq_entropies))
url_entropy_max = max(pathq_entropies)

# Phrase hits
phrase_hits = []
for p in PHISH_PHRASES:
    if p in full_text_l:
        phrase_hits.append(p)

# Simple style features
subject_len = len(subject)
subject_exclaim_count = subject.count("!")
body_exclaim_count = full_text.count("!")
digit_ratio = 0.0
if full_text:
    digit_ratio = float(sum(1 for c in full_text if c.isdigit())) / float(len(full_text))

upper_ratio = 0.0
letters = [c for c in subject if c.isalpha()]
if letters:
    upper_ratio = float(sum(1 for c in letters if c.isupper())) / float(len(letters))

# Optional DNS checks
dns_info = {
    "dns_attempted": False,
    "spf_record_found": False,
    "dkim_key_found": False,
    "spf_record": None,
    "dkim_selector": dkim_selector,
    "dkim_domain": dkim_domain,
    "dkim_key_snippet": None
}

if ENABLE_DNS_LOOKUPS:
    candidate_domain = from_domain or dkim_domain
    if candidate_domain:
        dns_info["dns_attempted"] = True
        try:
            spf_record = get_spf_record(candidate_domain)
            if spf_record:
                dns_info["spf_record_found"] = True
                dns_info["spf_record"] = spf_record[:500]
        except Exception:
            pass

    if dkim_selector and dkim_domain:
        dns_info["dns_attempted"] = True
        try:
            dkim_key = get_dkim_key(dkim_selector, dkim_domain)
            if dkim_key:
                dns_info["dkim_key_found"] = True
                dns_info["dkim_key_snippet"] = dkim_key[:120]
        except Exception:
            pass

# Teaching-friendly “signals”
signals = []

if spf_result in ("fail", "softfail", "permerror"):
    signals.append("SPF result indicates trouble: {0}".format(spf_result))
if dkim_result in ("fail", "permerror", "temperror"):
    signals.append("DKIM result indicates trouble: {0}".format(dkim_result))
if dmarc_result == "fail":
    signals.append("DMARC failed (alignment/policy signal)")

if reply_to_mismatch:
    signals.append("Reply-To domain differs from From domain (common phish pattern)")
if return_path_mismatch:
    signals.append("Return-Path domain differs from From domain (delivery-path mismatch)")
if has_password_field or (has_form and has_html):
    signals.append("HTML contains a form/password field (credential-harvest indicator)")
if has_suspicious_attachment:
    signals.append("Suspicious attachment extension detected")

if suspicious_flags.get("any_shortener"):
    signals.append("URL shortener present (can hide destination)")
if suspicious_flags.get("any_punycode") or suspicious_flags.get("any_non_ascii_domain"):
    signals.append("Potential IDN/punycode domain present (lookalike risk)")
if suspicious_flags.get("any_ip_host"):
    signals.append("URL host is a raw IP address (uncommon for legit org mail)")
if url_entropy_max >= 4.0:
    signals.append("High URL path/query entropy (often obfuscation / tracking / phish)")
if phrase_hits:
    preview = ", ".join(phrase_hits[:6])
    if len(phrase_hits) > 6:
        preview = preview + "..."
    signals.append("Phishy language patterns detected: {0}".format(preview))

# ------------------------------------------------------------
# OUTPUT (backwards-compatible keys + advanced fields)
# ------------------------------------------------------------
out = {
    "success": True,

    # Keep the core keys your Scoring_Engine likely expects
    "subject": subject,
    "from": from_h,
    "spf_result": spf_result,
    "dkim_result": dkim_result,
    "dmarc_result": dmarc_result,
    "body_len": len(full_text or ""),
    "phrase_hits": phrase_hits,
    "phrase_hit_count": len(phrase_hits),
    "url_entropy_mean": round(url_entropy_mean, 4),
    "url_entropy_max": round(url_entropy_max, 4),
    "url_count": len(url_features),
    "url_features": url_features,

    # Extra explainable / advanced fields
    "headers": {
        "from_addr": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "reply_domain": reply_domain,
        "return_path": return_path,
        "return_path_domain": rp_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "message_id_present": bool((message_id or "").strip()),
        "date": date_h,
        "authentication_results": authres[:5000],
        "received_spf": recv_spf[:2000]
    },

    "content": {
        "has_html": has_html,
        "has_form": has_form,
        "has_password_field": has_password_field,
        "subject_len": subject_len,
        "subject_upper_ratio": round(upper_ratio, 4),
        "subject_exclaim_count": subject_exclaim_count,
        "body_exclaim_count": body_exclaim_count,
        "digit_ratio": round(digit_ratio, 4)
    },

    "urls_meta": {
        "unique_domain_count": unique_domain_count,
        "unique_domains": unique_domains[:50],
        "suspicious_flags": suspicious_flags
    },

    "attachments": {
        "count": len(attachments),
        "has_suspicious_attachment": has_suspicious_attachment,
        "items": attachments[:50]
    },

    "dns": dns_info,
    "signals": signals
}

# ------------------------------------------------------------
# Compatibility layer for Scoring_Engine.py
# Scoring Engine expects: auth, urls, content, headers, attachments, dns
# ------------------------------------------------------------

# Ensure headers contains subject (Scoring Engine reads headers.subject)
try:
    if "headers" not in out or not isinstance(out.get("headers"), dict):
        out["headers"] = {}
    out["headers"]["subject"] = subject
except Exception:
    pass

# Ensure content contains the fields Scoring Engine expects
try:
    if "content" not in out or not isinstance(out.get("content"), dict):
        out["content"] = {}
    out["content"]["phrase_hit_count"] = int(len(phrase_hits))
    out["content"]["reply_to_mismatch"] = bool(reply_to_mismatch)
    # has_form / has_password_field already exist, but enforce anyway
    out["content"]["has_form"] = bool(has_form)
    out["content"]["has_password_field"] = bool(has_password_field)
except Exception:
    pass

# Build auth block expected by Scoring Engine
out["auth"] = {
    "spf_result": spf_result,
    "dkim_result": dkim_result,
    "dmarc_result": dmarc_result
}

# Build urls block expected by Scoring Engine
# Note: your current script uses urls_meta; Scoring Engine expects urls.suspicious_flags
out["urls"] = {
    "url_entropy_max": round(float(url_entropy_max), 4),
    "url_entropy_mean": round(float(url_entropy_mean), 4),
    "url_count": int(len(url_features)),
    "suspicious_flags": suspicious_flags
}

print(json.dumps(out))
