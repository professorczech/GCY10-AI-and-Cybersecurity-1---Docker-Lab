import json
import re

# ------------------------------------------------------------
# Scalar pulls from Feature Extractor output (NO raw email)
# Keep the same style as Scoring_Engine.bk.py, just more fields.
# ------------------------------------------------------------

# Core identity (optional, used only for evidence)
SUBJECT = r'''{{ $feature_extractor.message.subject }}'''
FROM_ADDR = r'''{{ $feature_extractor.message.from }}'''
FROM_DOMAIN = r'''{{ $feature_extractor.message.headers.from_domain }}'''

# Auth block (Feature_Extractor builds out["auth"] = {...})
SPF_RESULT  = r'''{{ $feature_extractor.message.auth.spf_result }}'''
DKIM_RESULT = r'''{{ $feature_extractor.message.auth.dkim_result }}'''
DMARC_RESULT= r'''{{ $feature_extractor.message.auth.dmarc_result }}'''

# URL block (Feature_Extractor builds out["urls"] = {...})
URL_ENTROPY_MAX  = r'''{{ $feature_extractor.message.urls.url_entropy_max }}'''
URL_ENTROPY_MEAN = r'''{{ $feature_extractor.message.urls.url_entropy_mean }}'''
URL_COUNT        = r'''{{ $feature_extractor.message.urls.url_count }}'''

# URL suspicious flags (Feature_Extractor mirrors suspicious_flags into urls.suspicious_flags)
ANY_SHORTENER        = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_shortener }}'''
ANY_IP_HOST          = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_ip_host }}'''
ANY_PUNYCODE         = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_punycode }}'''
ANY_SUSPICIOUS_TLD   = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_suspicious_tld }}'''
ANY_NON_ASCII_DOMAIN = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_non_ascii_domain }}'''
ANY_AT_IN_URL        = r'''{{ $feature_extractor.message.urls.suspicious_flags.any_at_in_url }}'''

# Content signals
PHRASE_HIT_COUNT   = r'''{{ $feature_extractor.message.content.phrase_hit_count }}'''
HAS_HTML           = r'''{{ $feature_extractor.message.content.has_html }}'''
HAS_FORM           = r'''{{ $feature_extractor.message.content.has_form }}'''
HAS_PASSWORD_FIELD = r'''{{ $feature_extractor.message.content.has_password_field }}'''
SUBJECT_UPPER_RATIO= r'''{{ $feature_extractor.message.content.subject_upper_ratio }}'''
SUBJECT_EXCLAIMS   = r'''{{ $feature_extractor.message.content.subject_exclaim_count }}'''
BODY_EXCLAIMS      = r'''{{ $feature_extractor.message.content.body_exclaim_count }}'''
DIGIT_RATIO        = r'''{{ $feature_extractor.message.content.digit_ratio }}'''

# Header mismatch signals
REPLY_TO_MISMATCH     = r'''{{ $feature_extractor.message.headers.reply_to_mismatch }}'''
RETURN_PATH_MISMATCH  = r'''{{ $feature_extractor.message.headers.return_path_mismatch }}'''
MESSAGE_ID_PRESENT    = r'''{{ $feature_extractor.message.headers.message_id_present }}'''

# Attachments
ATTACHMENT_COUNT          = r'''{{ $feature_extractor.message.attachments.count }}'''
HAS_SUSPICIOUS_ATTACHMENT = r'''{{ $feature_extractor.message.attachments.has_suspicious_attachment }}'''

# ----------------------------
# Converters (very tolerant)
# ----------------------------

def _looks_unexpanded(s: str) -> bool:
    t = (s or "").strip()
    return t.startswith("{{") and t.endswith("}}")

def clean_str(s: str, default=""):
    if s is None:
        return default
    t = str(s).strip()
    if not t or t.lower() in ("null", "none", "undefined"):
        return default
    if _looks_unexpanded(t):
        return default
    return t

def to_float(s, default=0.0):
    try:
        t = clean_str(s, "")
        return float(t) if t != "" else float(default)
    except Exception:
        return float(default)

def to_int(s, default=0):
    try:
        t = clean_str(s, "")
        return int(float(t)) if t != "" else int(default)
    except Exception:
        return int(default)

def to_bool(s):
    t = clean_str(s, "").lower()
    if t in ("true", "1", "yes", "y", "on"):
        return True
    if t in ("false", "0", "no", "n", "off", ""):
        return False
    # If Liquid ever outputs Python booleans
    if t == "true":
        return True
    return False

# ----------------------------
# Pull + normalize fields
# ----------------------------

subject = clean_str(SUBJECT, "")
from_addr = clean_str(FROM_ADDR, "")
from_domain = clean_str(FROM_DOMAIN, "")

spf = clean_str(SPF_RESULT, "unknown").lower()
dkim = clean_str(DKIM_RESULT, "unknown").lower()
dmarc = clean_str(DMARC_RESULT, "unknown").lower()

url_entropy_max = to_float(URL_ENTROPY_MAX, 0.0)
url_entropy_mean = to_float(URL_ENTROPY_MEAN, 0.0)
url_count = to_int(URL_COUNT, 0)

any_shortener = to_bool(ANY_SHORTENER)
any_ip_host = to_bool(ANY_IP_HOST)
any_punycode = to_bool(ANY_PUNYCODE)
any_suspicious_tld = to_bool(ANY_SUSPICIOUS_TLD)
any_non_ascii_domain = to_bool(ANY_NON_ASCII_DOMAIN)
any_at_in_url = to_bool(ANY_AT_IN_URL)

phrase_hit_count = to_int(PHRASE_HIT_COUNT, 0)
has_html = to_bool(HAS_HTML)
has_form = to_bool(HAS_FORM)
has_password_field = to_bool(HAS_PASSWORD_FIELD)

subject_upper_ratio = to_float(SUBJECT_UPPER_RATIO, 0.0)
subject_exclaims = to_int(SUBJECT_EXCLAIMS, 0)
body_exclaims = to_int(BODY_EXCLAIMS, 0)
digit_ratio = to_float(DIGIT_RATIO, 0.0)

reply_to_mismatch = to_bool(REPLY_TO_MISMATCH)
return_path_mismatch = to_bool(RETURN_PATH_MISMATCH)
message_id_present = to_bool(MESSAGE_ID_PRESENT)

attachment_count = to_int(ATTACHMENT_COUNT, 0)
has_suspicious_attachment = to_bool(HAS_SUSPICIOUS_ATTACHMENT)

# If templates didn’t expand at all, bail with a clear error instead of nonsense scoring.
# (This avoids the “it ran but everything is default” confusion.)
must_have_any = [
    SPF_RESULT, URL_ENTROPY_MAX, PHRASE_HIT_COUNT, URL_COUNT,
]
if all(_looks_unexpanded(x.strip()) for x in must_have_any if (x or "").strip()):
    print(json.dumps({
        "success": False,
        "error": "Feature Extractor variables did not expand in Scoring Engine. Ensure the prior node is named 'feature_extractor' in this workflow.",
    }))
    raise SystemExit(0)

# ----------------------------
# Advanced scoring rules
# ----------------------------

risk = 0
triggers = []

def add(points, reason):
    global risk
    risk += int(points)
    triggers.append(reason)

# 1) Auth signals
if spf in ("fail", "softfail", "permerror"):
    add(35, f"SPF result: {spf}")
elif spf in ("temperror", "none"):
    add(10, f"SPF inconclusive: {spf}")

if dkim in ("fail", "permerror", "temperror"):
    add(20, f"DKIM result: {dkim}")
elif dkim == "none":
    add(6, "DKIM missing/none")

if dmarc == "fail":
    add(25, "DMARC failed")
elif dmarc == "none":
    add(6, "DMARC missing/none")

# 2) Header mismatch signals
if reply_to_mismatch:
    add(20, "Reply-To domain mismatch (common redirect-to-attacker pattern)")
if return_path_mismatch:
    add(15, "Return-Path mismatch (delivery path doesn’t align with From)")
if not message_id_present:
    add(6, "Missing Message-ID header (unusual for legit org mail)")

# 3) URL / link signals
if any_shortener:
    add(18, "URL shortener present (can hide destination)")
if any_ip_host:
    add(25, "URL host is a raw IP address (highly suspicious)")
if any_punycode or any_non_ascii_domain:
    add(20, "IDN/punycode or non-ASCII domain detected (lookalike risk)")
if any_suspicious_tld:
    add(12, "Suspicious TLD detected")
if any_at_in_url:
    add(12, "URL contains '@' (credential/confusion trick)")

# Entropy heuristics
if url_entropy_max >= 4.2:
    add(20, f"High URL path/query entropy (max={url_entropy_max})")
elif url_entropy_max >= 4.0:
    add(15, f"Elevated URL path/query entropy (max={url_entropy_max})")
elif url_entropy_mean >= 3.6:
    add(8, f"Moderately elevated avg URL entropy (mean={url_entropy_mean})")

# URL count heuristics
if url_count >= 8:
    add(10, f"Many URLs ({url_count})")
elif url_count >= 4:
    add(6, f"Multiple URLs ({url_count})")
elif url_count == 1 and any_shortener:
    add(6, "Single link + shortener combo (classic phish pattern)")

# 4) Content + phrasing
if phrase_hit_count >= 6:
    add(35, f"Very high phishy phrasing density ({phrase_hit_count} hits)")
elif phrase_hit_count >= 3:
    add(25, f"High phishy phrasing density ({phrase_hit_count} hits)")
elif phrase_hit_count > 0:
    add(10, f"Some risky phrasing present ({phrase_hit_count} hits)")

# HTML form/password field is a major indicator
if has_password_field:
    add(35, "HTML contains password field (credential-harvest indicator)")
elif has_form and has_html:
    add(22, "HTML contains a form (credential-harvest indicator)")
elif has_form:
    add(12, "Form detected")

# Subject heuristics (lightweight, avoid overfitting)
subj_l = (subject or "").lower()
if any(k in subj_l for k in ["action required", "verify", "password", "invoice", "security alert"]):
    add(8, "Subject contains urgency/account/security language")
if subject_upper_ratio >= 0.75:
    add(8, f"Subject is mostly uppercase (ratio={subject_upper_ratio})")
elif subject_upper_ratio >= 0.55:
    add(4, f"Subject has elevated uppercase ratio (ratio={subject_upper_ratio})")

if subject_exclaims >= 2:
    add(4, f"Multiple exclamation marks in subject ({subject_exclaims})")
if body_exclaims >= 4:
    add(3, f"Many exclamation marks in body ({body_exclaims})")
if digit_ratio >= 0.15:
    add(4, f"High digit ratio in body (ratio={digit_ratio})")

# 5) Attachments
if has_suspicious_attachment:
    add(40, "Suspicious attachment extension detected")
elif attachment_count > 0:
    add(8, f"Email has attachments ({attachment_count})")

# Cap the score
risk = max(0, min(100, risk))

# Verdict thresholds (tuned for your example: shortener + 'click here' should not be "Clean")
verdict = "Clean"
if risk >= 70:
    verdict = "Malicious"
elif risk >= 30:
    verdict = "Suspicious"

print(json.dumps({
    "success": True,
    "final_score": risk,
    "verdict": verdict,
    "triggers": triggers[:20],
    "evidence": {
        "subject": subject,
        "from": from_addr,
        "from_domain": from_domain,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "urls": {
            "url_entropy_max": url_entropy_max,
            "url_entropy_mean": url_entropy_mean,
            "url_count": url_count,
            "flags": {
                "any_shortener": any_shortener,
                "any_ip_host": any_ip_host,
                "any_punycode": any_punycode,
                "any_suspicious_tld": any_suspicious_tld,
                "any_non_ascii_domain": any_non_ascii_domain,
                "any_at_in_url": any_at_in_url,
            }
        },
        "content": {
            "phrase_hit_count": phrase_hit_count,
            "has_html": has_html,
            "has_form": has_form,
            "has_password_field": has_password_field,
            "subject_upper_ratio": subject_upper_ratio,
            "subject_exclaim_count": subject_exclaims,
            "body_exclaim_count": body_exclaims,
            "digit_ratio": digit_ratio
        },
        "headers": {
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "message_id_present": message_id_present
        },
        "attachments": {
            "count": attachment_count,
            "has_suspicious_attachment": has_suspicious_attachment
        }
    }
}))
