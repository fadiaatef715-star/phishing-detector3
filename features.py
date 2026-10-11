import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank",
                    "confirm", "password", "signin", "paypal", "free", "bonus",
                    "wallet", "suspend", "urgent", "payment"]
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu"]

FEATURE_NAMES = [
    "long_url",
    "many_dots",
    "has_at",
    "ip_address",
    "many_hyphens",
    "not_https",
    "bad_words",
    "many_subdomains",
    "many_digits",
    "bad_tld",
]


def extract_features(url):
    """يحوّل الرابط لقايمة أرقام بين 0 و1. الرقم الأكبر = أكتر شبهة"""
    url = str(url).strip()
    lower = url.lower()
    # نتجاهل www. لأن في الداتا كل الروابط السليمة فيها www (نمط مش حقيقي)
    lower = lower.replace("://www.", "://", 1)
    if lower.startswith("www."):
        lower = lower[4:]

    parsed = urlparse(lower if "://" in lower else "http://" + lower)
    host = parsed.netloc.split("@")[-1].split(":")[0]
    parts = [p for p in host.split(".") if p]
    tld = parts[-1] if parts else ""

    is_ip = 1.0 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else 0.0
    words = sum(1 for w in SUSPICIOUS_WORDS if w in lower)
    digits = sum(ch.isdigit() for ch in lower)

    return [
        min(len(host) / 30, 1.0),
        min(host.count(".") / 5, 1.0),
        1.0 if "@" in lower else 0.0,
        is_ip,
        min(host.count("-") / 3, 1.0),
        0.0 if lower.startswith("https://") else 1.0,
        min(words / 3, 1.0),
        min(max(len(parts) - 2, 0) / 3, 1.0),
        min(digits / 10, 1.0),
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,
    ]