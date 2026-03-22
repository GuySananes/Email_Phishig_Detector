import re
import difflib
from urllib.parse import urlparse


def detect_urgent_language(text):
    """
    Detects urgent keywords in the email text.
    Returns a list of found phrases.
    """
    urgent_keywords = [
        "urgent", "immediately", "action required",
        "verify now", "account suspended"
    ]

    found_phrases = []
    text_lower = text.lower()

    for keyword in urgent_keywords:
        if keyword in text_lower:
            found_phrases.append(keyword)

    return found_phrases


def extract_urls(text):
    """
    Extracts all URLs from the given text using a regular expression.
    """
    url_pattern = r'https?://[^\s<>"]+'
    return re.findall(url_pattern, text)


def analyze_url(url):
    """
    Analyzes a single URL for suspicious characteristics.
    """
    suspicious_reasons = []

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
    except ValueError:
        return ["Invalid URL format"]

    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    if ip_pattern.search(domain):
        suspicious_reasons.append("IP address used instead of a domain name")

    if domain.count('-') > 2:
        suspicious_reasons.append("Multiple hyphens in domain (often used to confuse users)")

    if "paypa1" in domain:
        suspicious_reasons.append("Brand spoofing detected (looks like 'paypal')")

    if len(url) > 80:
        suspicious_reasons.append("URL is suspiciously long")

    return suspicious_reasons


def extract_sender(text):
    """
    Extracts the sender's email address from the 'From:' header.
    """
    match = re.search(r'^From:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1)
    return None


def analyze_sender(sender_email):
    """
    Analyzes the sender's email domain for spoofing attempts against trusted domains.
    """
    trusted_domains = ["paypal.com", "amazon.com", "google.com", "microsoft.com", "upwind.io"]

    try:
        domain = sender_email.split('@')[1].lower()
    except IndexError:
        return "Invalid email format"

    if domain in trusted_domains:
        return None

    for trusted in trusted_domains:
        similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()
        if 0.8 <= similarity < 1.0:
            return f"Spoofed sender detected! '{domain}' is suspiciously similar to '{trusted}'"

    return None