# 🛡️ Phishing Email Detective & Threat Forensics App

A Streamlit web application (`app.py`) for analyzing pasted email text or uploaded `.eml` files for phishing clues. It performs deep inspection of email headers, extracts and analyzes embedded URLs, flags psychological urgency triggers, and displays a responsive **Risk Score (0–100) Gauge Chart** with clear forensic explanations.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.10+ (Tested on Python 3.14)
- Streamlit
- Pandas

### 2. Launch the Application
Run the following command from this directory:
```bash
streamlit run app.py
```
Or directly with your Python executable:
```powershell
& "C:\Users\ameym\AppData\Local\Programs\Python\Python314\Scripts\streamlit.exe" run app.py
```

The app will open automatically in your browser at `http://localhost:8501`.

---

## 🔍 Key Detection Features

### 1. Sender vs. Reply-To Mismatches & Header Forensics
- **Divergent Reply-To Routing**: Flags emails where the `From` domain and `Reply-To` domain differ, preventing stealth response diversion.
- **Display Name Spoofing**: Detects when the sender's display name impersonates known brands (e.g., *PayPal Support*, *Microsoft Office 365*) or executive titles (*CEO*, *CFO*, *Helpdesk*) while sending from a consumer webmail address (e.g., `@gmail.com`).
- **Embedded Address Deception**: Catches attackers placing fake addresses inside the display name string (e.g., `"support@bank.com <attacker@phish.xyz>"`).
- **Authentication Header Verification**: Parses `Authentication-Results` for `spf=fail`, `dkim=fail`, and `dmarc=fail` flags.

### 2. Deep URL & Hyperlink Inspection
- **Anchor Text vs. Destination Mismatch**: Highlights dangerous links where the visible link text displays a trusted site (e.g. `https://paypal.com/login`), but the underlying `href` routes to an attacker's IP or malicious host.
- **Direct IP Address Hosts**: Flags raw IP endpoints (e.g., `http://192.168.1.105/auth.php`).
- **High-Abuse TLDs**: Flags domains using top-level domains commonly abused in phishing (`.xyz`, `.top`, `.click`, `.buzz`, `.cam`, etc.).
- **URL Shorteners**: Flags masking services (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
- **Punycode / Homograph Detection**: Catches internationalized domain name spoofing (`xn--...`).
- **Brand Impersonation in Domains**: Detects brand keywords placed in subdomains of unauthorized domains.

### 3. Psychological Coercion & Urgency Engine
Scans email text against 5 key social engineering categories:
1. **Urgency & Deadlines** (*"immediate action required"*, *"within 24 hours"*, *"final notice"*)
2. **Fear & Account Penalties** (*"account suspended"*, *"access restricted"*, *"unauthorized access"*)
3. **Credential Demands** (*"verify your password"*, *"update billing"*, *"validate account"*)
4. **Financial & Wire Lures** (*"wire transfer"*, *"direct deposit"*, *"invoice overdue"*)
5. **Call-to-Action Traps** (*"click here to verify"*, *"open the attachment"*)

Includes an **Interactive Live Text Preview** where all detected trigger keywords are highlighted with color-coded badges directly in the message body.

### 4. Attachment Security & MIME Analysis
- Detects dangerous file extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.iso`, `.docm`).
- Identifies **double extension evasion** (e.g., `invoice_9302.pdf.exe`).
- Flags archive containers used to bypass basic email filters (`.zip`, `.rar`, `.7z`).

### 5. Risk Score Gauge Chart & Clear Explanations
- **Retina SVG Speedometer Gauge**: Calibrated from 0 (Safe) to 100 (Critical Phishing Threat) with 3 color-coded danger zones (Emerald Green, Amber Warning, Crimson Danger) and dynamic needle pivot.
- **Categorized Risk Breakdown**: Visual progress bars showing exact point contributions from Headers, URLs, Urgency, and Attachments.
- **Actionable Guidance**: Clear safety instructions (e.g. SOC escalation, out-of-band verification).
- **Exportable Forensic Audit**: 1-click download of full forensic reports in **Markdown** (`.md`) or **JSON** (`.json`).

---

## 🧪 Pre-Loaded Demonstrations
The app includes 4 pre-configured real-world email templates:
- 🎣 **Phishing**: PayPal Credential Harvester (mismatched Reply-To, deceptive anchor text, direct IP host)
- 💼 **BEC Scam**: CEO Wire Fraud Impersonation (free webmail, extreme urgency, wire transfer lure)
- 🔑 **Phishing**: Microsoft 365 Password Expiration (shortened URL, 12-hour deadline)
- 🟢 **Legitimate**: Authentic GitHub Pro Billing Receipt (aligned headers, trusted domain, standard tone)

---

## 📁 Project Structure
```text
phishing-email-analyzer/
├── app.py              # Main Streamlit web application
├── analyzer.py         # Forensic analysis engine (headers, URLs, keywords, scoring)
├── components.py       # SVG Gauge chart & keyword highlighting UI components
├── samples.py          # Realistic pre-loaded email samples
├── sample_phish.eml    # Sample RFC 822 email file for upload testing
├── test_analyzer.py    # Automated test suite (9 unit tests)
└── README.md           # Documentation & usage guide
```
