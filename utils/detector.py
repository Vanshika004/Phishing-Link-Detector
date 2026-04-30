import base64
import ipaddress
import os
import re
from typing import Dict, List
from urllib.parse import urlparse

import requests


SUSPICIOUS_KEYWORDS = ["login", "verify", "bank", "secure", "update"]
VIRUSTOTAL_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
VIRUSTOTAL_TIMEOUT_SECONDS = 12


def is_valid_url(url: str) -> bool:
    if not isinstance(url, str) or not url.strip():
        return False

    parsed = urlparse(url.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def classify_score(score: int) -> str:
    if score >= 6:
        return "Phishing"
    if score >= 3:
        return "Suspicious"
    return "Safe"


def hostname_uses_ip(hostname: str) -> bool:
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def virustotal_url_id(url: str) -> str:
    """VirusTotal identifies URL resources by URL-safe base64 without padding."""
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def submit_to_virustotal(url: str, api_key: str) -> str | None:
    # Kept for clarity with VirusTotal's URL encoding model.
    virustotal_url_id(url)

    response = requests.post(
        VIRUSTOTAL_SUBMIT_URL,
        headers={"x-apikey": api_key},
        data={"url": url},
        timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    data = response.json()
    return data.get("data", {}).get("id")


def fetch_virustotal_result(analysis_id: str, api_key: str) -> Dict:
    response = requests.get(
        VIRUSTOTAL_ANALYSIS_URL.format(analysis_id=analysis_id),
        headers={"x-apikey": api_key},
        timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def check_virustotal(url: str) -> Dict[str, int | str | bool]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {"available": False, "error": "VirusTotal API key not configured"}

    try:
        analysis_id = submit_to_virustotal(url, api_key)
        if not analysis_id:
            return {"available": False, "error": "VirusTotal did not return an analysis ID"}

        result = fetch_virustotal_result(analysis_id, api_key)
        stats = (
            result.get("data", {})
            .get("attributes", {})
            .get("stats", {})
        )

        return {
            "available": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
        }
    except requests.RequestException as error:
        return {"available": False, "error": f"VirusTotal request failed: {error}"}
    except (TypeError, ValueError) as error:
        return {"available": False, "error": f"VirusTotal response was invalid: {error}"}


def detect_url(url: str, hidden: bool = False, link_text: str = "") -> Dict[str, int | str | List[str]]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()
    domain = hostname.lower()
    score = 0
    reasons: List[str] = []

    if "@" in url:
        score += 2
        reasons.append("URL contains '@', which can hide the real destination")

    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    matched_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in full_url]
    if matched_keywords:
        score += len(matched_keywords)
        reasons.append(f"Contains suspicious keyword(s): {', '.join(matched_keywords)}")

    if hostname_uses_ip(hostname):
        score += 2
        reasons.append("URL uses an IP address instead of a domain name")

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 1
        reasons.append("Domain contains too many hyphens")

    if parsed.scheme != "https":
        score += 1
        reasons.append("URL does not use HTTPS")

    if hidden:
        score += 2
        reasons.append("Link is hidden or visually invisible on the page")

    if not link_text.strip():
        score += 1
        reasons.append("Link has no visible text")

    if re.search(r"(.)\1{4,}", domain):
        score += 1
        reasons.append("Domain contains repeated characters")

    vt_result = check_virustotal(url)
    if vt_result.get("available"):
        malicious = int(vt_result.get("malicious", 0))
        suspicious = int(vt_result.get("suspicious", 0))

        if malicious > 0:
            score += 4
            reasons.append("Flagged by VirusTotal")
        elif suspicious > 0:
            score += 2
            reasons.append("Marked suspicious by VirusTotal")
    elif vt_result.get("error") and vt_result.get("error") != "VirusTotal API key not configured":
        reasons.append(str(vt_result["error"]))

    if not reasons:
        reasons.append("No suspicious indicators found")

    return {
        "result": classify_score(score),
        "score": score,
        "reasons": reasons,
    }
