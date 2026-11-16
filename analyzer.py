"""
Phishing Email Analyzer Engine
Analyzes email headers, body, URLs, urgency keywords, and attachments
to calculate a comprehensive Phishing Risk Score (0-100).
"""

import re
import html
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any, Tuple, Optional

# --- Suspicious TLDs and URL Shorteners ---
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "buzz", "club", "work", "fit", "rest", "cam",
    "gq", "cf", "tk", "ml", "ga", "ru", "cn", "cc", "to", "site", "space",
    "monster", "info", "loan", "stream", "live", "date", "racing", "vip", "icu",
    "surf", "wang", "kim", "country", "download", "review"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink"
}

HIGH_PROFILE_BRANDS = [
    "paypal", "microsoft", "office365", "apple", "icloud", "amazon", "google",
    "gmail", "netflix", "chase", "wellsfargo", "bankofamerica", "citi",
    "citibank", "dhl", "fedex", "ups", "usps", "facebook", "meta", "instagram",
    "linkedin", "dropbox", "docusign", "adobe", "secure-bank", "binance",
    "coinbase", "metamask", "ebay", "walmart", "irs", "hmrc"
]

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "zoho.com", "mail.com", "yandex.com",
    "icloud.com", "gmx.com", "fastmail.com"
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "vbs", "js", "wsf", "ps1", "iso", "img",
    "docm", "xlsm", "pptm", "hta", "jar", "apk", "com", "pif", "dll"
}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "cab", "bz2"}

# --- Urgency, Threat, and Coercion Keywords ---
KEYWORD_CATEGORIES = {
    "Urgency & Deadlines": {
        "weight": 8,
        "keywords": [
            "immediate action required", "immediately", "within 24 hours", "within 12 hours",
            "within 48 hours", "urgent action", "act now", "time sensitive", "time-sensitive",
            "expires today", "expires soon", "deadline", "final notice", "final warning",
            "last reminder", "don't delay", "promptly", "action required immediately",
            "respond immediately", "instant verification"
        ]
    },
    "Fear & Account Penalties": {
        "weight": 10,
        "keywords": [
            "account suspended", "account blocked", "account locked", "account terminated",
            "access restricted", "suspended temporarily", "unauthorized access", "unusual activity",
            "suspicious login", "security breach", "compromised", "fraud detected",
            "legal action", "law enforcement", "arrest warrant", "penalty", "account closure",
            "permanently deleted", "permanently disabled", "unauthorized transaction",
            "security alert", "critical alert"
        ]
    },
    "Credential & Verification Demands": {
        "weight": 9,
        "keywords": [
            "verify your account", "verify your identity", "confirm your password",
            "reset your password", "update your credentials", "validate your account",
            "click here to login", "sign in to verify", "update billing information",
            "confirm your identity", "re-activate your account", "unlock your account",
            "security update required", "enter your passcode", "confirm ownership"
        ]
    },
    "Financial & Wire Lures": {
        "weight": 9,
        "keywords": [
            "wire transfer", "direct deposit", "gift card", "bitcoin", "cryptocurrency",
            "crypto wallet", "invoice overdue", "overdue payment", "payment failed",
            "payroll update", "tax refund", "refund notification", "reimbursement",
            "bonus payment", "lottery winner", "inheritance", "million dollars",
            "compensation fund", "unclaimed funds"
        ]
    },
    "Call to Action / Generic Traps": {
        "weight": 5,
        "keywords": [
            "click here", "click below", "open the attachment", "download the attached",
            "view attached document", "verify now", "update now", "claim now",
            "access your account now"
        ]
    }
}


def extract_domain(email_or_url: str) -> str:
    """Extract clean lowercase domain from email address or URL."""
    if not email_or_url:
        return ""
    
    # If it's an email address
    if "@" in email_or_url:
        parts = email_or_url.split("@")
        domain = parts[-1].strip().rstrip(">").rstrip("]").lower()
        return domain
    
    # If it's a URL
    try:
        if not email_or_url.startswith(("http://", "https://")):
            email_or_url = "http://" + email_or_url
        parsed = urlparse(email_or_url)
        netloc = parsed.netloc.split(":")[0].lower()
        return netloc
    except Exception:
        return ""


def parse_email_headers_and_body(raw_content: str, is_bytes: bool = False, raw_bytes: bytes = None) -> Dict[str, Any]:
    """
    Parse an email message (from raw text or bytes).
    Handles standard RFC 5322 .eml format or plaintext email drafts.
    """
    if is_bytes and raw_bytes:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    else:
        # Check if text looks like RFC 822 / MIME format
        if "\n\n" in raw_content or "\r\n\r\n" in raw_content or any(h in raw_content[:400] for h in ["From:", "Subject:", "To:"]):
            msg = Parser(policy=policy.default).parsestr(raw_content)
        else:
            msg = None

    result = {
        "headers": {},
        "from_header": "",
        "from_name": "",
        "from_address": "",
        "from_domain": "",
        "reply_to_header": "",
        "reply_to_address": "",
        "reply_to_domain": "",
        "return_path": "",
        "to_header": "",
        "subject": "",
        "date": "",
        "authentication_results": "",
        "body_plain": "",
        "body_html": "",
        "attachments": [],
        "is_parsed_eml": False
    }

    if msg and (msg.get("From") or msg.get("Subject") or msg.get("To")):
        result["is_parsed_eml"] = True
        
        # Headers
        result["from_header"] = str(msg.get("From", "") or "")
        result["reply_to_header"] = str(msg.get("Reply-To", "") or "")
        result["return_path"] = str(msg.get("Return-Path", "") or "")
        result["to_header"] = str(msg.get("To", "") or "")
        result["subject"] = str(msg.get("Subject", "") or "")
        result["date"] = str(msg.get("Date", "") or "")
        result["authentication_results"] = str(msg.get("Authentication-Results", "") or "") + " " + str(msg.get("Received-SPF", "") or "")
        
        # Parse From name and address
        name, addr = email.utils.parseaddr(result["from_header"])
        result["from_name"] = name
        result["from_address"] = addr.lower()
        result["from_domain"] = extract_domain(result["from_address"])
        
        # Parse Reply-To address
        _, rep_addr = email.utils.parseaddr(result["reply_to_header"])
        result["reply_to_address"] = rep_addr.lower()
        result["reply_to_domain"] = extract_domain(result["reply_to_address"])
        
        # Collect all raw headers
        for k, v in msg.items():
            result["headers"][k] = str(v)
            
        # Extract plain and HTML bodies
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition") or "")
                    
                    if "attachment" in content_disposition:
                        filename = part.get_filename() or "unnamed_attachment"
                        result["attachments"].append({
                            "filename": filename,
                            "content_type": content_type,
                            "size": len(part.get_payload(decode=True) or b"")
                        })
                    elif content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            result["body_plain"] += payload.decode(errors="ignore") + "\n"
                    elif content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            result["body_html"] += payload.decode(errors="ignore") + "\n"
            else:
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                decoded = payload.decode(errors="ignore") if payload else str(msg.get_payload() or "")
                if content_type == "text/html":
                    result["body_html"] = decoded
                else:
                    result["body_plain"] = decoded
        except Exception:
            result["body_plain"] = raw_content
    else:
        # Fallback: Plain text paste without full MIME structure
        # Attempt simple regex extraction for From:, Reply-To:, Subject: if present
        result["body_plain"] = raw_content
        from_match = re.search(r"(?:^|\n)From:\s*(.+)", raw_content, re.IGNORECASE)
        reply_to_match = re.search(r"(?:^|\n)Reply-To:\s*(.+)", raw_content, re.IGNORECASE)
        subject_match = re.search(r"(?:^|\n)Subject:\s*(.+)", raw_content, re.IGNORECASE)
        to_match = re.search(r"(?:^|\n)To:\s*(.+)", raw_content, re.IGNORECASE)
        
        if from_match:
            result["from_header"] = from_match.group(1).strip()
            name, addr = email.utils.parseaddr(result["from_header"])
            result["from_name"] = name
            result["from_address"] = addr.lower()
            result["from_domain"] = extract_domain(result["from_address"])
            
        if reply_to_match:
            result["reply_to_header"] = reply_to_match.group(1).strip()
            _, rep_addr = email.utils.parseaddr(result["reply_to_header"])
            result["reply_to_address"] = rep_addr.lower()
            result["reply_to_domain"] = extract_domain(result["reply_to_address"])
            
        if subject_match:
            result["subject"] = subject_match.group(1).strip()
            
        if to_match:
            result["to_header"] = to_match.group(1).strip()

    return result


def extract_and_analyze_urls(plain_text: str, html_content: str) -> List[Dict[str, Any]]:
    """
    Extract all URLs from plain text and HTML.
    Performs deep inspection:
    - Anchor text mismatch (e.g. text says paypal.com but href goes to evil.ru)
    - IP address hosts
    - Suspicious TLDs
    - Shorteners
    - Brand impersonation in subdomains
    - Punycode / Homograph attacks
    """
    found_urls = []
    seen = set()

    # 1. Extract from HTML anchors if present
    if html_content:
        # Regex to find <a ... href="URL" ...>TEXT</a>
        a_tag_pattern = re.compile(r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        for href, inner_text in a_tag_pattern.findall(html_content):
            clean_href = html.unescape(href).strip()
            clean_text = re.sub(r'<[^>]+>', '', inner_text).strip()
            clean_text = html.unescape(clean_text)
            
            if clean_href.startswith(("http://", "https://", "ftp://")):
                key = (clean_href, clean_text)
                if key not in seen:
                    seen.add(key)
                    found_urls.append({
                        "url": clean_href,
                        "display_text": clean_text,
                        "source": "HTML Link"
                    })

    # 2. Extract plain text URLs
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
    for match in url_pattern.finditer(plain_text or ""):
        u = match.group(0).rstrip(".,;!?:)")
        key = (u, "")
        if key not in seen and not any(f["url"] == u for f in found_urls):
            seen.add(key)
            found_urls.append({
                "url": u,
                "display_text": "",
                "source": "Plain Text"
            })

    # Now inspect each URL for threats
    inspected = []
    for item in found_urls:
        url = item["url"]
        display = item["display_text"]
        source = item["source"]
        
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        tld = hostname.split(".")[-1] if "." in hostname else ""
        
        flags = []
        risk_contribution = 0
        
        # Check A: Anchor text mismatch
        if display and (display.startswith("http://") or display.startswith("https://") or "www." in display or ".com" in display):
            disp_domain = extract_domain(display)
            if disp_domain and hostname and disp_domain != hostname:
                # Big red flag: text displays one domain, but links elsewhere
                flags.append(f"Mismatched Anchor: displays '{disp_domain}', actual destination is '{hostname}'")
                risk_contribution += 35

        # Check B: IP address host
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(hostname):
            flags.append(f"Direct IP Host detected ({hostname}) - common in malicious payloads")
            risk_contribution += 30

        # Check C: Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"High-abuse TLD (.{tld}) commonly used in phishing campaigns")
            risk_contribution += 18

        # Check D: URL Shortener
        if hostname in URL_SHORTENERS:
            flags.append(f"URL Shortener ({hostname}) masks true destination")
            risk_contribution += 15

        # Check E: Punycode / Homograph
        if hostname.startswith("xn--") or "xn--" in hostname:
            flags.append("Punycode (IDN homograph) detected in domain name")
            risk_contribution += 25

        # Check F: Brand Impersonation in non-official domain
        for brand in HIGH_PROFILE_BRANDS:
            if brand in hostname:
                # Is brand the main domain or a deception?
                official_domains = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"login.{brand}.com"]
                if not any(hostname == off or hostname.endswith("." + off) for off in official_domains):
                    flags.append(f"Potential Brand Impersonation: '{brand}' found in suspicious host '{hostname}'")
                    risk_contribution += 28
                    break

        # Check G: Multiple @ symbols or userinfo trick
        if "@" in parsed.netloc:
            flags.append("Credential/Domain Confusion: URL contains '@' character in authority segment")
            risk_contribution += 25

        # Check H: Insecure HTTP for sensitive-looking URL
        if parsed.scheme == "http" and any(k in url.lower() for k in ["login", "signin", "account", "banking", "verify", "secure"]):
            flags.append("Insecure HTTP used on sensitive authentication/account endpoint")
            risk_contribution += 12

        inspected.append({
            "url": url,
            "display_text": display,
            "source": source,
            "hostname": hostname,
            "tld": tld,
            "flags": flags,
            "risk_contribution": min(risk_contribution, 50)
        })

    return inspected


def analyze_urgency_and_keywords(text: str) -> Dict[str, Any]:
    """
    Search for phishing trigger keywords across multiple behavioral categories:
    Urgency, Fear, Credential harvesting, Financial lures, and Generic traps.
    """
    lowered = text.lower()
    matches_by_category = {}
    total_keyword_risk = 0
    total_found_count = 0

    for cat_name, cat_data in KEYWORD_CATEGORIES.items():
        weight = cat_data["weight"]
        found_in_cat = []
        
        for kw in cat_data["keywords"]:
            # Word boundary matching where appropriate
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            finds = list(pattern.finditer(lowered))
            if finds:
                # Extract snippet for context
                first_find = finds[0]
                start = max(0, first_find.start() - 30)
                end = min(len(text), first_find.end() + 30)
                snippet = "..." + text[start:end].replace("\n", " ").strip() + "..."
                
                found_in_cat.append({
                    "keyword": kw,
                    "count": len(finds),
                    "snippet": snippet
                })
                total_found_count += len(finds)

        if found_in_cat:
            cat_score = min(len(found_in_cat) * weight, 30)
            total_keyword_risk += cat_score
            matches_by_category[cat_name] = {
                "matches": found_in_cat,
                "score": cat_score
            }

    # Normalize total keyword risk (capped at 40 points)
    normalized_score = min(total_keyword_risk, 40)
    
    return {
        "categories": matches_by_category,
        "total_keyword_risk": normalized_score,
        "total_found_count": total_found_count
    }


def analyze_sender_and_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze sender identity, From vs Reply-To mismatches,
    display name spoofing, and authentication headers.
    """
    from_name = parsed_email.get("from_name", "")
    from_addr = parsed_email.get("from_address", "")
    from_domain = parsed_email.get("from_domain", "")
    reply_to = parsed_email.get("reply_to_address", "")
    reply_to_domain = parsed_email.get("reply_to_domain", "")
    auth_results = parsed_email.get("authentication_results", "").lower()
    return_path = parsed_email.get("return_path", "").lower()
    
    flags = []
    positive_indicators = []
    risk_score = 0

    # 1. Reply-To vs From Domain Mismatch
    if reply_to and from_addr:
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            flags.append({
                "severity": "HIGH",
                "title": "Sender vs. Reply-To Domain Mismatch",
                "description": f"Email claims to come from '{from_domain}', but replies are routed to '{reply_to_domain}' ({reply_to}). This is a classic tactic used by attackers to divert responses.",
                "points": 35
            })
            risk_score += 35
        elif reply_to != from_addr:
            flags.append({
                "severity": "MEDIUM",
                "title": "Reply-To Address Differs from Sender",
                "description": f"From: {from_addr} vs Reply-To: {reply_to}. While occasionally legitimate, this warrants caution.",
                "points": 15
            })
            risk_score += 15
        else:
            positive_indicators.append("Reply-To address matches Sender address.")
    elif from_addr:
        positive_indicators.append("No diverging Reply-To header specified.")

    # 2. Display Name Spoofing
    # e.g., Display name is "PayPal Support" or "CEO Name" but email is attacker@gmail.com
    lower_from_name = from_name.lower()
    for brand in HIGH_PROFILE_BRANDS:
        if brand in lower_from_name:
            if brand not in from_domain:
                flags.append({
                    "severity": "HIGH",
                    "title": f"Display Name Spoofing ({brand.title()})",
                    "description": f"Display name contains recognized brand '{brand.title()}', but sender address domain is '{from_domain}'.",
                    "points": 30
                })
                risk_score += 30
                break

    # Look for executive impersonation or authority titles paired with free webmail
    authority_titles = ["ceo", "cfo", "director", "president", "hr department", "helpdesk", "it support", "administrator", "billing department"]
    for title in authority_titles:
        if title in lower_from_name and from_domain in FREE_MAIL_PROVIDERS:
            flags.append({
                "severity": "HIGH",
                "title": "Executive / Authority Impersonation on Free Webmail",
                "description": f"Sender uses authority title '{title.upper()}' with a free consumer webmail domain ({from_domain}).",
                "points": 30
            })
            risk_score += 30
            break

    # Display name contains an embedded email address that doesn't match
    embedded_email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_name)
    if embedded_email_match:
        embedded_addr = embedded_email_match.group(0).lower()
        if embedded_addr != from_addr:
            flags.append({
                "severity": "CRITICAL",
                "title": "Deceptive Display Name (Embedded Fake Address)",
                "description": f"Display name shows '{embedded_addr}', but actual sending mailbox is '{from_addr}'.",
                "points": 35
            })
            risk_score += 35

    # 3. Authentication Results (SPF, DKIM, DMARC)
    if auth_results:
        if "spf=fail" in auth_results or "spf=softfail" in auth_results:
            flags.append({
                "severity": "HIGH",
                "title": "SPF Authentication Failed",
                "description": "Sending mail server is not authorized to send on behalf of this domain.",
                "points": 25
            })
            risk_score += 25
        elif "spf=pass" in auth_results:
            positive_indicators.append("SPF check passed.")

        if "dkim=fail" in auth_results:
            flags.append({
                "severity": "HIGH",
                "title": "DKIM Cryptographic Signature Invalid",
                "description": "Email content or headers appear to have been altered in transit.",
                "points": 25
            })
            risk_score += 25
        elif "dkim=pass" in auth_results:
            positive_indicators.append("DKIM cryptographic signature passed.")

        if "dmarc=fail" in auth_results:
            flags.append({
                "severity": "CRITICAL",
                "title": "DMARC Policy Enforcement Failed",
                "description": "Domain alignment failed DMARC policy validation.",
                "points": 30
            })
            risk_score += 30
        elif "dmarc=pass" in auth_results:
            positive_indicators.append("DMARC alignment passed.")

    # 4. Return-Path Mismatch
    if return_path and from_domain:
        rp_domain = extract_domain(return_path)
        if rp_domain and rp_domain != from_domain:
            flags.append({
                "severity": "LOW",
                "title": "Return-Path Domain Divergence",
                "description": f"Return-Path is '{rp_domain}' while From domain is '{from_domain}'. (May occur in marketing tools, but also used in bounce evasion).",
                "points": 8
            })
            risk_score += 8

    return {
        "flags": flags,
        "positive_indicators": positive_indicators,
        "risk_score": min(risk_score, 50)
    }


def analyze_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Inspect email attachments for dangerous executables, archives, and double extensions."""
    flags = []
    risk_score = 0
    
    for att in attachments:
        filename = att.get("filename", "")
        parts = filename.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        
        # Check double extension
        if len(parts) > 2 and parts[-1] in DANGEROUS_EXTENSIONS:
            flags.append({
                "severity": "CRITICAL",
                "filename": filename,
                "title": "Deceptive Double Extension",
                "description": f"Attachment '{filename}' uses a double extension to mask an executable payload."
            })
            risk_score += 40
        elif ext in DANGEROUS_EXTENSIONS:
            flags.append({
                "severity": "HIGH",
                "filename": filename,
                "title": "High-Risk Executable Attachment",
                "description": f"Attachment '{filename}' has a dangerous file extension (.{ext})."
            })
            risk_score += 35
        elif ext in ARCHIVE_EXTENSIONS:
            flags.append({
                "severity": "MEDIUM",
                "filename": filename,
                "title": "Archive Attachment",
                "description": f"Attachment '{filename}' is an archive file (.{ext}) often used to conceal malicious scripts."
            })
            risk_score += 15

    return {
        "flags": flags,
        "risk_score": min(risk_score, 40),
        "total_attachments": len(attachments)
    }


def calculate_overall_risk(
    header_analysis: Dict[str, Any],
    url_analysis: List[Dict[str, Any]],
    urgency_analysis: Dict[str, Any],
    attachment_analysis: Dict[str, Any],
    subject: str = ""
) -> Dict[str, Any]:
    """
    Synthesize all risk vectors into an overall Risk Score (0 - 100),
    providing a transparent breakdown, threat classification, and verdict.
    """
    # 1. Header points
    header_points = header_analysis["risk_score"]
    
    # 2. URL points (sum up top url risks, cap at 45)
    url_total = sum(u.get("risk_contribution", 0) for u in url_analysis)
    url_points = min(url_total, 45)
    
    # 3. Urgency points (cap at 35)
    urgency_points = urgency_analysis["total_keyword_risk"]
    
    # 4. Attachment points (cap at 30)
    attachment_points = attachment_analysis["risk_score"]
    
    # 5. Subject heuristics (All Caps, Re:/Fwd: spoofing)
    subject_points = 0
    if subject:
        if subject.isupper() and len(subject) > 10:
            subject_points += 8
        if re.match(r'^(re|fwd):\s*', subject, re.IGNORECASE) and not header_analysis.get("positive_indicators"):
            subject_points += 5

    # Composite Raw Score
    raw_score = header_points + url_points + urgency_points + attachment_points + subject_points
    
    # Boost if multiple independent critical vectors match (compound risk)
    critical_triggers = 0
    if header_points >= 25:
        critical_triggers += 1
    if any(len(u.get("flags", [])) > 0 for u in url_analysis):
        critical_triggers += 1
    if urgency_points >= 18:
        critical_triggers += 1
    if attachment_points >= 25:
        critical_triggers += 1

    multiplier = 1.0
    if critical_triggers >= 3:
        multiplier = 1.25
    elif critical_triggers == 2:
        multiplier = 1.1

    final_score = int(round(min(raw_score * multiplier, 100.0)))
    
    # Classification
    if final_score >= 70:
        verdict = "HIGH RISK PHISHING"
        verdict_color = "#EF4444" # Red
        verdict_class = "danger"
        summary = "CRITICAL: This email exhibits strong indicators of a malicious phishing or social engineering attack. DO NOT click links, download attachments, or reply."
    elif final_score >= 35:
        verdict = "SUSPICIOUS / ELEVATED RISK"
        verdict_color = "#F59E0B" # Amber / Orange
        verdict_class = "warning"
        summary = "WARNING: Several suspicious signals were detected. Exercise extreme caution, inspect links carefully, and verify the sender out-of-band before taking any action."
    else:
        verdict = "LOW RISK / LIKELY LEGITIMATE"
        verdict_color = "#10B981" # Emerald Green
        verdict_class = "safe"
        summary = "CLEAN: No prominent phishing hallmarks or deceptive patterns were found. Normal vigilance is still recommended."

    breakdown = {
        "Sender & Headers": header_points,
        "Links & URLs": url_points,
        "Urgency & Psychological Coercion": urgency_points,
        "Attachments": attachment_points,
        "Subject / Structure": subject_points
    }

    return {
        "score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_class": verdict_class,
        "summary": summary,
        "breakdown": breakdown,
        "critical_trigger_count": critical_triggers
    }
