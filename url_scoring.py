from typing import Optional
from urllib.parse import urlparse

import tldextract

from utils import (
    vt_url_lookup,
    vt_domain_lookup,
    whois_lookup,
    dns_lookup,
    parse_html,
    detect_homograph,
    is_ip_address,
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
)


# URL Analysis – Scoring Functions

def analyze_url_structure(url: str) -> tuple[int, list[str]]:
    """
    Analyse the raw URL string for structural red-flags.

    Checks performed:
      • Excessive length (>100 chars)
      • Suspicious characters (@ sign, % encoding, multiple dots)
      • IP address used instead of domain name
      • Known URL shortener domains
      • Suspicious TLDs (.tk, .xyz, …)
      • Homograph / look-alike domains imitating popular brands
    """
    score = 0
    reasons: list[str] = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    extracted = tldextract.extract(url)
    tld = extracted.suffix.split(".")[-1].lower() if extracted.suffix else ""

    if len(url) > 200:
        score += 15
        reasons.append(f"Very long URL ({len(url)} chars)")
    elif len(url) > 100:
        score += 5
        reasons.append(f"Long URL ({len(url)} chars)")

    if "@" in url:
        score += 10
        reasons.append("URL contains '@' – possible credential-based redirect")

    pct_count = url.count("%")
    if pct_count > 4:
        score += 15
        reasons.append(f"Excessive percent-encoding ({pct_count} occurrences)")

    dot_count = hostname.count(".")
    if dot_count >= 4:
        score += 10
        reasons.append(f"Excessive subdomains in hostname ({dot_count} dots)")

    if is_ip_address(hostname):
        score += 30
        reasons.append(f"URL uses raw IP address: {hostname}")

    full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    if full_domain in URL_SHORTENERS:
        score += 15
        reasons.append(f"URL shortener detected: {full_domain}")

    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"Suspicious TLD: .{tld}")

    brand = detect_homograph(hostname)
    if brand:
        score += 40
        reasons.append(f"Possible homograph / look-alike of '{brand}'")

    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS")

    return score, reasons


def analyze_domain_intelligence(domain: str) -> tuple[int, list[str]]:
    """
    Use WHOIS and DNS data to assess domain trustworthiness.

    Risk rules:
      • Domain age < 30 days → +30
      • Domain age < 90 days → +15
      • Hidden WHOIS / privacy guard → +10
      • No DNS records at all → +20
    """
    score = 0
    reasons: list[str] = []

    # --- WHOIS ---
    whois_data = whois_lookup(domain)

    if whois_data.get("error"):
        score += 10
        reasons.append(f"WHOIS lookup failed: {whois_data['error']}")
    else:
        age = whois_data.get("domain_age_days")
        if age is not None:
            if age < 30:
                score += 30
                reasons.append(f"Very new domain (registered {age} days ago)")
            elif age < 90:
                score += 15
                reasons.append(f"Recently registered domain ({age} days ago)")

        if whois_data.get("whois_hidden"):
            score += 10
            reasons.append("WHOIS information is hidden / privacy-protected")

        registrar = whois_data.get("registrar")
        if registrar:
            reasons.append(f"Registrar: {registrar}")

    # --- DNS ---
    dns_data = dns_lookup(domain)
    if dns_data.get("error"):
        score += 20
        reasons.append("No DNS records found for domain")

    return score, reasons


def analyze_page_content(html: str, redirect_count: int) -> tuple[int, list[str]]:
    """
    Analyse fetched HTML content for phishing / malicious signals.

    Checks:
      • Hidden iframes
      • External suspicious scripts
      • Obfuscated JavaScript (eval, atob, unescape …)
      • Login forms (phishing indicator)
      • Suspicious urgency keywords
      • Excessive redirects (≥3)
    """
    score = 0
    reasons: list[str] = []

    if not html:
        return score, reasons

    signals = parse_html(html)

    # --- Hidden iframes ---
    if signals["hidden_iframes"]:
        count = len(signals["hidden_iframes"])
        score += 30
        reasons.append(f"Hidden iframe(s) detected ({count}): {signals['hidden_iframes'][:3]}")

    # --- External scripts ---
    ext_scripts = signals["external_scripts"]
    if len(ext_scripts) > 10:
        score += 10
        reasons.append(f"Large number of external scripts ({len(ext_scripts)})")

    # --- Obfuscated JS ---
    if signals["obfuscated_js"]:
        funcs = list(set(signals["obfuscated_js"]))
        score += 25
        reasons.append(f"Obfuscated JavaScript detected: {', '.join(funcs[:5])}")

    # --- Login form ---
    if signals["login_forms"]:
        score += 20
        reasons.append("Page contains a login/password form (possible phishing)")

    # --- Suspicious keywords ---
    if signals["suspicious_keywords"]:
        kw_score = min(len(signals["suspicious_keywords"]) * 5, 20)
        score += kw_score
        reasons.append(f"Suspicious keywords: {', '.join(signals['suspicious_keywords'][:5])}")

    # --- Redirects ---
    if redirect_count >= 5:
        score += 20
        reasons.append(f"Excessive redirects ({redirect_count})")
    elif redirect_count >= 3:
        score += 10
        reasons.append(f"Multiple redirects ({redirect_count})")

    return score, reasons


def analyze_threat_intelligence(url: str, domain: str) -> tuple[int, list[str]]:
    """
    Query external threat-intelligence services:
      • VirusTotal URL report
      • VirusTotal domain report

    Returns score contribution and explanation list.
    """
    score = 0
    reasons: list[str] = []

    # --- VirusTotal URL ---
    vt_url = vt_url_lookup(url)
    if vt_url:
        if vt_url["malicious"] > 0:
            score += 60
            reasons.append(
                f"VirusTotal: URL flagged as malicious by "
                f"{vt_url['malicious']} engine(s)"
            )
        elif vt_url["suspicious"] > 0:
            score += 30
            reasons.append(
                f"VirusTotal: URL flagged as suspicious by "
                f"{vt_url['suspicious']} engine(s)"
            )

    # --- VirusTotal Domain ---
    vt_dom = vt_domain_lookup(domain)
    if vt_dom:
        if vt_dom["malicious"] > 0:
            score += 40
            reasons.append(
                f"VirusTotal: domain flagged as malicious by "
                f"{vt_dom['malicious']} engine(s)"
            )
        elif vt_dom["suspicious"] > 0:
            score += 20
            reasons.append(
                f"VirusTotal: domain flagged as suspicious by "
                f"{vt_dom['suspicious']} engine(s)"
            )

    return score, reasons


def compute_url_score(
    url: str,
    html_body: str = "",
    redirect_count: int = 0,
    fetch_error: Optional[str] = None,
) -> dict:
    """
    Master scoring function for URL analysis.

    Aggregates results from:
      1. URL structure analysis
      2. Domain intelligence (WHOIS + DNS)
      3. Page content analysis (HTML / JS)
      4. Threat intelligence (VirusTotal)

    Verdict thresholds:
      score <  30  → SAFE
      score 30–60  → SUSPICIOUS
      score >  60  → MALICIOUS

    Returns a dict with score, verdict, and reasons list.
    """
    total_score = 0
    all_reasons: list[str] = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}".lower()

    # 1. URL structure
    s, r = analyze_url_structure(url)
    total_score += s
    all_reasons.extend(r)

    # 2. Domain intelligence (skip for raw IPs)
    if not is_ip_address(hostname):
        s, r = analyze_domain_intelligence(domain)
        total_score += s
        all_reasons.extend(r)

    # 3. Content analysis
    if html_body:
        s, r = analyze_page_content(html_body, redirect_count)
        total_score += s
        all_reasons.extend(r)
    elif fetch_error:
        all_reasons.append(f"Could not fetch page content: {fetch_error}")

    # 4. Threat intelligence
    s, r = analyze_threat_intelligence(url, domain)
    total_score += s
    all_reasons.extend(r)

    # --- Final verdict ---
    if total_score > 60:
        verdict = "MALICIOUS"
    elif total_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    if not all_reasons:
        all_reasons.append("No indicators triggered")

    return {
        "url": url,
        "domain": domain,
        "score": total_score,
        "verdict": verdict,
        "reasons": all_reasons,
    }
