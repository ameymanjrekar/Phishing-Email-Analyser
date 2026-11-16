"""
Comprehensive Test Suite for Phishing Email Analyzer
Tests headers, URLs, urgency keywords, attachments, and risk scores.
"""

import unittest
from analyzer import (
    parse_email_headers_and_body,
    extract_and_analyze_urls,
    analyze_urgency_and_keywords,
    analyze_sender_and_headers,
    analyze_attachments,
    calculate_overall_risk,
    extract_domain
)
from samples import (
    SAMPLE_PAYPAL_PHISHING,
    SAMPLE_CEO_FRAUD,
    SAMPLE_MICROSOFT_PASSWORD,
    SAMPLE_LEGITIMATE_RECEIPT
)


class TestPhishingAnalyzer(unittest.TestCase):

    def test_domain_extraction(self):
        self.assertEqual(extract_domain("user@example.com"), "example.com")
        self.assertEqual(extract_domain("<support@sub.domain.org>"), "sub.domain.org")
        self.assertEqual(extract_domain("https://secure.chase.com/login"), "secure.chase.com")
        self.assertEqual(extract_domain("http://192.168.1.1:8080/path"), "192.168.1.1")

    def test_sender_reply_to_mismatch(self):
        parsed = {
            "from_name": "PayPal Support",
            "from_address": "support@paypal.com",
            "from_domain": "paypal.com",
            "reply_to_address": "harvest@evil-phish.xyz",
            "reply_to_domain": "evil-phish.xyz",
            "authentication_results": "",
            "return_path": ""
        }
        res = analyze_sender_and_headers(parsed)
        # Should flag domain mismatch with high severity
        mismatch_flags = [f for f in res["flags"] if "Mismatch" in f["title"]]
        self.assertTrue(len(mismatch_flags) > 0)
        self.assertGreaterEqual(res["risk_score"], 35)

    def test_display_name_spoofing(self):
        parsed = {
            "from_name": "Microsoft Security Alert",
            "from_address": "randomuser392@gmail.com",
            "from_domain": "gmail.com",
            "reply_to_address": "",
            "reply_to_domain": "",
            "authentication_results": "",
            "return_path": ""
        }
        res = analyze_sender_and_headers(parsed)
        spoof_flags = [f for f in res["flags"] if "Spoofing" in f["title"] or "Impersonation" in f["title"]]
        self.assertTrue(len(spoof_flags) > 0)

    def test_url_mismatched_anchor(self):
        html_content = '<p>Click <a href="http://192.168.1.50/login">https://www.paypal.com/signin</a> to verify.</p>'
        urls = extract_and_analyze_urls("", html_content)
        self.assertEqual(len(urls), 1)
        flags = urls[0]["flags"]
        # Should flag both mismatched anchor and direct IP host
        self.assertTrue(any("Mismatched Anchor" in f for f in flags))
        self.assertTrue(any("Direct IP Host" in f for f in flags))

    def test_url_shortener_and_suspicious_tld(self):
        plain_text = "Check out https://bit.ly/m365-alert and http://banking-safety.xyz/update"
        urls = extract_and_analyze_urls(plain_text, "")
        self.assertEqual(len(urls), 2)
        all_flags = [f for u in urls for f in u["flags"]]
        self.assertTrue(any("URL Shortener" in f for f in all_flags))
        self.assertTrue(any("High-abuse TLD" in f for f in all_flags))

    def test_urgency_keywords_detection(self):
        text = "Your account has been suspended! Immediate action required within 24 hours to confirm your password and avoid legal action."
        urg = analyze_urgency_and_keywords(text)
        self.assertGreater(urg["total_found_count"], 0)
        self.assertIn("Urgency & Deadlines", urg["categories"])
        self.assertIn("Fear & Account Penalties", urg["categories"])
        self.assertIn("Credential & Verification Demands", urg["categories"])

    def test_attachment_danger_detection(self):
        attachments = [
            {"filename": "document.pdf.exe", "content_type": "application/octet-stream", "size": 1024},
            {"filename": "normal_invoice.pdf", "content_type": "application/pdf", "size": 20480}
        ]
        res = analyze_attachments(attachments)
        self.assertEqual(len(res["flags"]), 1)
        self.assertEqual(res["flags"][0]["title"], "Deceptive Double Extension")

    def test_paypal_phishing_sample(self):
        parsed = parse_email_headers_and_body(SAMPLE_PAYPAL_PHISHING)
        urls = extract_and_analyze_urls(parsed["body_plain"], parsed["body_html"])
        urg = analyze_urgency_and_keywords(parsed["body_plain"] + " " + parsed["body_html"])
        snd = analyze_sender_and_headers(parsed)
        att = analyze_attachments(parsed["attachments"])
        risk = calculate_overall_risk(snd, urls, urg, att, parsed["subject"])
        
        self.assertGreaterEqual(risk["score"], 70)
        self.assertEqual(risk["verdict"], "HIGH RISK PHISHING")

    def test_clean_sample(self):
        parsed = parse_email_headers_and_body(SAMPLE_LEGITIMATE_RECEIPT)
        urls = extract_and_analyze_urls(parsed["body_plain"], parsed["body_html"])
        urg = analyze_urgency_and_keywords(parsed["body_plain"] + " " + parsed["body_html"])
        snd = analyze_sender_and_headers(parsed)
        att = analyze_attachments(parsed["attachments"])
        risk = calculate_overall_risk(snd, urls, urg, att, parsed["subject"])
        
        self.assertLess(risk["score"], 30)
        self.assertEqual(risk["verdict"], "LOW RISK / LIKELY LEGITIMATE")


if __name__ == "__main__":
    unittest.main()
