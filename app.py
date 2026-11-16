"""
Phishing Email Analyzer Web App
Streamlit application that analyzes pasted email text or uploaded .eml files
for phishing clues: sender vs. reply-to mismatches, URL extraction & threat inspection,
urgency keywords, and a Risk Score gauge chart with clear explanations.
"""

import json
import streamlit as st
import pandas as pd
from typing import Dict, Any

from analyzer import (
    parse_email_headers_and_body,
    extract_and_analyze_urls,
    analyze_urgency_and_keywords,
    analyze_sender_and_headers,
    analyze_attachments,
    calculate_overall_risk
)
from components import (
    render_svg_gauge,
    render_breakdown_bars,
    highlight_keywords_in_text
)
from samples import SAMPLES

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="Phishing Email Analyzer & Forensic Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS Styling ---
st.markdown("""
<style>
    /* Global styles */
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #0F172A;
        margin-bottom: 0.2rem;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .subtitle {
        color: #475569;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        margin-bottom: 14px;
    }
    .card-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 700;
        color: #64748B;
        margin-bottom: 6px;
    }
    .card-value {
        font-size: 1.4rem;
        font-weight: 800;
        color: #0F172A;
    }
    .flag-high {
        background-color: #FEF2F2;
        border-left: 4px solid #EF4444;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 10px;
    }
    .flag-med {
        background-color: #FFFBEB;
        border-left: 4px solid #F59E0B;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 10px;
    }
    .flag-ok {
        background-color: #F0FDF4;
        border-left: 4px solid #10B981;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .action-box {
        background: #F8FAFC;
        border: 1px solid #CBD5E1;
        border-radius: 10px;
        padding: 16px;
        margin-top: 15px;
    }
    .badge {
        display: inline-block;
        padding: 2px 8px;
        font-size: 11px;
        font-weight: 700;
        border-radius: 4px;
        text-transform: uppercase;
    }
    .badge-danger { background: #FEE2E2; color: #991B1B; }
    .badge-warning { background: #FEF3C7; color: #92400E; }
    .badge-success { background: #DCFCE7; color: #166534; }
    .badge-info { background: #E0F2FE; color: #075985; }
</style>
""", unsafe_allow_html=True)


# --- Sidebar Navigation & Education ---
with st.sidebar:
    st.markdown("### 🛡️ Phishing Defense Lab")
    st.info(
        "**What does this tool check?**\n\n"
        "1. **Sender vs. Reply-To Mismatch**: Diverging response routing\n"
        "2. **Deceptive URLs**: Fake anchors, IP hosts, suspicious TLDs, shorteners\n"
        "3. **Psychological Coercion**: Artificial urgency, account threats, credential traps\n"
        "4. **Attachment Security**: Executable payloads, masked double extensions\n"
        "5. **Domain Spoofing**: Brand impersonation on free webmail"
    )
    
    st.markdown("---")
    st.markdown("#### 🚨 Common Phishing Red Flags")
    with st.expander("1. Display Name vs Address", expanded=False):
        st.caption("Attackers use legitimate-looking display names (e.g. *PayPal Alerts*) with completely unrelated Gmail or malicious domains.")
    with st.expander("2. Anchor Text Deception", expanded=False):
        st.caption("The text on screen shows `https://bank.com`, but the actual link destination points to a phishing harvest server.")
    with st.expander("3. Artificial Urgency", expanded=False):
        st.caption("Phrases like *'Within 24 hours'*, *'Account Suspended'*, or *'Wire immediately'* manipulate victims to act without thinking.")
    with st.expander("4. Free Webmail from Executives", expanded=False):
        st.caption("CEOs or VIPs requesting urgent transfers or gift cards from `@gmail.com` or `@proton.me`.")

    st.markdown("---")
    st.caption("Antigravity Cybersecurity Suite • Powered by Python 3.14 & Streamlit")


# --- Main Header ---
st.markdown('<div class="main-title"><span>🛡️</span> Phishing Email Detective & Threat Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Inspect email headers, verify sender identities, extract embedded URLs, flag psychological coercion tactics, and view a visual Risk Score gauge.</div>', unsafe_allow_html=True)


# --- Input Mode Selection ---
input_mode = st.radio(
    "Choose Input Method:",
    options=["📋 Paste Email Text", "📁 Upload .eml File", "🧪 Try Pre-Loaded Samples"],
    horizontal=True
)

raw_email_text = ""
uploaded_file_bytes = None
is_file_mode = False

if input_mode == "🧪 Try Pre-Loaded Samples":
    sample_choice = st.selectbox(
        "Select a Pre-Loaded Demonstration Email:",
        options=list(SAMPLES.keys())
    )
    raw_email_text = SAMPLES[sample_choice]
    st.caption("💡 The selected email sample is automatically loaded into the analysis pipeline.")

elif input_mode == "📁 Upload .eml File":
    uploaded_file = st.file_uploader(
        "Upload an email file (.eml, .txt)",
        type=["eml", "txt", "msg"],
        help="Upload standard RFC 822 .eml export from Outlook, Gmail, Thunderbird, or Apple Mail."
    )
    if uploaded_file is not None:
        uploaded_file_bytes = uploaded_file.read()
        is_file_mode = True
        st.success(f"Loaded file: `{uploaded_file.name}` ({len(uploaded_file_bytes):,} bytes)")
    else:
        st.info("Upload any `.eml` file to begin forensic parsing.")

else:  # Paste Email Text
    st.markdown("Paste the raw email content below. You can include email headers (`From:`, `Subject:`, etc.) or paste just the message body.")
    raw_email_text = st.text_area(
        "Email Content:",
        value="",
        height=220,
        placeholder="From: Security Team <security@bank-alert.xyz>\nReply-To: harvest@malicious-domain.com\nSubject: Urgent: Verify Account\n\nDear customer, your account will be suspended within 24 hours..."
    )
    
    with st.expander("🛠️ Optional: Override / Specify Headers Manually", expanded=False):
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            manual_from = st.text_input("Sender (From):", placeholder="e.g. CEO <ceo@company.com>")
            manual_subject = st.text_input("Subject:", placeholder="e.g. Urgent Wire Transfer Request")
        with col_h2:
            manual_reply_to = st.text_input("Reply-To:", placeholder="e.g. attacker@proton.me")
            manual_to = st.text_input("Recipient (To):", placeholder="e.g. victim@company.com")
            
        if manual_from or manual_reply_to or manual_subject:
            # Prepend manual headers if provided
            header_prefix = ""
            if manual_from: header_prefix += f"From: {manual_from}\n"
            if manual_reply_to: header_prefix += f"Reply-To: {manual_reply_to}\n"
            if manual_to: header_prefix += f"To: {manual_to}\n"
            if manual_subject: header_prefix += f"Subject: {manual_subject}\n"
            raw_email_text = header_prefix + "\n" + raw_email_text


# --- Action Button ---
col_btn, col_hint = st.columns([1, 4])
with col_btn:
    analyze_btn = st.button("🔍 Analyze Email", type="primary", use_container_width=True)

with col_hint:
    if input_mode == "🧪 Try Pre-Loaded Samples":
        st.write("Ready to analyze pre-loaded sample. Click **Analyze Email** to run.")


# --- Execution Pipeline ---
if analyze_btn or (input_mode == "🧪 Try Pre-Loaded Samples" and raw_email_text):
    if not is_file_mode and not raw_email_text.strip():
        st.warning("⚠️ Please paste email text or upload an .eml file before analyzing.")
        st.stop()

    with st.spinner("Analyzing email headers, extracting URLs, scanning urgency triggers..."):
        # 1. Parse Email
        if is_file_mode and uploaded_file_bytes:
            parsed = parse_email_headers_and_body("", is_bytes=True, raw_bytes=uploaded_file_bytes)
        else:
            parsed = parse_email_headers_and_body(raw_email_text)

        # Combine text sources for keyword analysis
        combined_text = (parsed.get("subject", "") + " " + 
                         parsed.get("body_plain", "") + " " + 
                         parsed.get("body_html", ""))

        # 2. Forensic Analysis Modules
        urls = extract_and_analyze_urls(parsed.get("body_plain", ""), parsed.get("body_html", ""))
        urgency = analyze_urgency_and_keywords(combined_text)
        sender_analysis = analyze_sender_and_headers(parsed)
        attachment_analysis = analyze_attachments(parsed.get("attachments", []))
        
        # 3. Overall Risk Calculation
        risk = calculate_overall_risk(
            header_analysis=sender_analysis,
            url_analysis=urls,
            urgency_analysis=urgency,
            attachment_analysis=attachment_analysis,
            subject=parsed.get("subject", "")
        )

    # =========================================================================
    # RESULTS DASHBOARD
    # =========================================================================
    st.markdown("---")
    st.markdown("## 📊 Forensic Investigation Dashboard")

    # Top Row: Gauge Chart (Left) & Verdict / Executive Summary (Right)
    top_col_gauge, top_col_summary = st.columns([1.2, 1.8])

    with top_col_gauge:
        st.markdown("#### Phishing Risk Gauge")
        svg_gauge_html = render_svg_gauge(risk["score"], risk["verdict"], risk["verdict_color"])
        st.html(svg_gauge_html)
        st.caption("Speedometer gauge calibrated from 0 (Safe) to 100 (Critical Phishing Threat).")

    with top_col_summary:
        st.markdown("#### Threat Summary & Verdict")
        
        # Verdict Banner
        if risk["verdict_class"] == "danger":
            st.error(f"### 🚨 {risk['verdict']}\n\n**{risk['summary']}**")
        elif risk["verdict_class"] == "warning":
            st.warning(f"### ⚠️ {risk['verdict']}\n\n**{risk['summary']}**")
        else:
            st.success(f"### ✅ {risk['verdict']}\n\n**{risk['summary']}**")

        # Metric KPI cards
        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
        with kpi_col1:
            st.metric("Header Risk", f"{sender_analysis['risk_score']} pts")
        with kpi_col2:
            st.metric("Extracted URLs", f"{len(urls)} found")
        with kpi_col3:
            st.metric("Urgency Triggers", f"{urgency['total_found_count']} flags")
        with kpi_col4:
            st.metric("Attachments", f"{len(parsed.get('attachments', []))} files")

        # Recommended Action
        st.markdown('<div class="action-box">', unsafe_allow_html=True)
        st.markdown("**🛡️ Recommended Security Actions:**")
        if risk["score"] >= 70:
            st.markdown("""
            - 🛑 **DO NOT CLICK** any links or open any attachments.
            - 🛑 **DO NOT REPLY** or confirm your credentials, password, or banking information.
            - 🔒 Forward this email as an attachment to your IT Security / SOC department.
            - 🗑️ Mark as Phishing in your email client and delete immediately.
            """)
        elif risk["score"] >= 35:
            st.markdown("""
            - ⚠️ Verify the sender's identity through a separate, trusted channel (phone call or direct message).
            - ⚠️ Hover over links and inspect destination domains before considering interaction.
            - ⚠️ Never submit passwords or banking credentials on pages linked from unverified emails.
            """)
        else:
            st.markdown("""
            - ✅ Standard vigilance: The message appears consistent with legitimate communication.
            - Always maintain caution when receiving unexpected requests for payment or login.
            """)
        st.markdown('</div>', unsafe_allow_html=True)

    # Risk Contribution Breakdown Bars
    st.markdown("#### 📈 Threat Vector Contribution Breakdown")
    st.html(render_breakdown_bars(risk["breakdown"]))

    # =========================================================================
    # DETAILED INVESTIGATION TABS
    # =========================================================================
    st.markdown("---")
    tab_urls, tab_sender, tab_urgency, tab_attach, tab_raw, tab_export = st.tabs([
        "🔗 URL & Link Forensics",
        "✉️ Sender & Header Alignment",
        "⚠️ Urgency & Keyword Clues",
        "📎 Attachments & Structure",
        "📄 Email Body & Raw Headers",
        "📋 Export Forensic Report"
    ])

    # --- TAB 1: URL & Link Forensics ---
    with tab_urls:
        st.markdown("### 🔗 URL Extraction & Threat Inspection")
        if not urls:
            st.info("ℹ️ No hyperlinks or URLs were detected in this email.")
        else:
            st.write(f"Detected **{len(urls)}** distinct link(s). Each link was evaluated for deceptive display anchors, IP hosts, suspicious TLDs, and brand impersonation:")
            
            url_records = []
            for idx, u in enumerate(urls, start=1):
                url_records.append({
                    "#": idx,
                    "Destination URL": u["url"],
                    "Display / Anchor Text": u["display_text"] if u["display_text"] else "(None / Raw URL)",
                    "Domain / Host": u["hostname"],
                    "Flags & Threats": " | ".join(u["flags"]) if u["flags"] else "✅ Clean Domain Structure",
                    "Risk Impact": f"+{u['risk_contribution']} pts"
                })
            
            df_urls = pd.DataFrame(url_records)
            st.dataframe(df_urls, use_container_width=True, hide_index=True)

            # Highlight specific dangerous URLs
            flagged_urls = [u for u in urls if u["flags"]]
            if flagged_urls:
                st.markdown("#### 🚨 High-Risk URL Detail Cards")
                for u in flagged_urls:
                    st.markdown(f"""
                    <div class="flag-high">
                        <strong>Target:</strong> <code>{u['url']}</code><br>
                        <strong>Anchor / Display Text:</strong> <code>{u['display_text'] or 'N/A'}</code><br>
                        <strong>Detected Threats:</strong>
                        <ul>
                            {"".join([f"<li>{f}</li>" for f in u['flags']])}
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)

    # --- TAB 2: Sender & Header Alignment ---
    with tab_sender:
        st.markdown("### ✉️ Sender Identity vs. Reply-To Alignment")
        
        col_from, col_reply = st.columns(2)
        with col_from:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">From (Sender Header)</div>', unsafe_allow_html=True)
            st.markdown(f"**Display Name:** `{parsed.get('from_name') or 'None'}`")
            st.markdown(f"**Email Address:** `{parsed.get('from_address') or 'Not specified'}`")
            st.markdown(f"**Domain:** `{parsed.get('from_domain') or 'None'}`")
            st.markdown('</div>', unsafe_allow_html=True)

        with col_reply:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">Reply-To (Routing Header)</div>', unsafe_allow_html=True)
            st.markdown(f"**Email Address:** `{parsed.get('reply_to_address') or 'Same as From'}`")
            st.markdown(f"**Domain:** `{parsed.get('reply_to_domain') or 'Same as From'}`")
            st.markdown(f"**Return-Path:** `{parsed.get('return_path') or 'Not specified'}`")
            st.markdown('</div>', unsafe_allow_html=True)

        # Domain Alignment Result Card
        st.markdown("#### 🔍 Domain Alignment Audit")
        if parsed.get("from_domain") and parsed.get("reply_to_domain") and parsed.get("from_domain") != parsed.get("reply_to_domain"):
            st.error(f"""
            🚨 **CRITICAL MISMATCH DETECTED:**  
            The sender domain (`{parsed.get('from_domain')}`) does **NOT** match the reply-to domain (`{parsed.get('reply_to_domain')}`).  
            Any response sent to this email will be secretly diverted to `{parsed.get('reply_to_address')}`.
            """)
        else:
            st.success("✅ **Domain Alignment:** Sender domain and Reply-To domain are aligned or consistent.")

        # Header Flags and Findings
        st.markdown("#### 📋 Header Security Flags")
        if sender_analysis["flags"]:
            for flag in sender_analysis["flags"]:
                sev = flag.get("severity", "MEDIUM")
                cls_name = "flag-high" if sev in ["CRITICAL", "HIGH"] else "flag-med"
                badge_type = "badge-danger" if sev in ["CRITICAL", "HIGH"] else "badge-warning"
                st.markdown(f"""
                <div class="{cls_name}">
                    <span class="badge {badge_type}">{sev}</span>
                    <strong>{flag['title']}</strong> (+{flag['points']} pts)<br>
                    <span>{flag['description']}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No suspicious header anomalies or display name spoofing detected.")

        if sender_analysis["positive_indicators"]:
            st.markdown("#### 🛡️ Positive Indicators")
            for ind in sender_analysis["positive_indicators"]:
                st.markdown(f'<div class="flag-ok">✅ {ind}</div>', unsafe_allow_html=True)

    # --- TAB 3: Urgency & Keyword Clues ---
    with tab_urgency:
        st.markdown("### ⚠️ Psychological Coercion & Urgency Detection")
        st.write("Phishing emails exploit psychological triggers—such as artificial urgency, fear of account loss, and credential verification traps—to bypass critical thinking.")

        if not urgency["categories"]:
            st.success("✅ No prominent urgency or high-pressure coercion keywords were identified.")
        else:
            col_cats, col_prev = st.columns([1, 1.2])
            
            with col_cats:
                st.markdown("#### Trigger Categories Found")
                for cat_name, cat_data in urgency["categories"].items():
                    with st.expander(f"📁 {cat_name} (+{cat_data['score']} pts)", expanded=True):
                        for m in cat_data["matches"]:
                            st.markdown(f"- **`{m['keyword']}`** (matched {m['count']}x)")
                            st.caption(f"Context: {m['snippet']}")

            with col_prev:
                st.markdown("#### Body Text with Highlighted Keywords")
                body_to_highlight = parsed.get("body_plain") or parsed.get("body_html") or raw_email_text
                st.html(highlight_keywords_in_text(body_to_highlight, urgency["categories"]))
                st.caption("Color-coded tags highlight urgency (yellow), threats/penalties (red), credential demands (purple), and financial lures (green).")

    # --- TAB 4: Attachments & Structure ---
    with tab_attach:
        st.markdown("### 📎 Attachment Security & MIME Analysis")
        attachments = parsed.get("attachments", [])
        
        if not attachments:
            st.info("ℹ️ No attachments were found in this message.")
        else:
            st.write(f"Found **{len(attachments)}** attachment(s):")
            att_records = []
            for a in attachments:
                att_records.append({
                    "Filename": a["filename"],
                    "MIME Type": a["content_type"],
                    "Size": f"{a['size']:,} bytes"
                })
            st.dataframe(pd.DataFrame(att_records), use_container_width=True, hide_index=True)

        if attachment_analysis["flags"]:
            st.markdown("#### 🚨 Dangerous Attachment Alerts")
            for f in attachment_analysis["flags"]:
                st.markdown(f"""
                <div class="flag-high">
                    <span class="badge badge-danger">{f['severity']}</span>
                    <strong>{f['title']}:</strong> <code>{f['filename']}</code><br>
                    <span>{f['description']}</span>
                </div>
                """, unsafe_allow_html=True)

    # --- TAB 5: Email Body & Raw Headers ---
    with tab_raw:
        st.markdown("### 📄 Extracted Content & Full Headers")
        
        col_txt, col_hdr = st.columns(2)
        with col_txt:
            st.markdown("#### Plain Text / Rendered Body")
            display_text = parsed.get("body_plain") or "No plain text part found."
            st.text_area("Extracted Plain Text", value=display_text, height=350, disabled=True)
            
            if parsed.get("body_html"):
                with st.expander("Show Raw HTML Source", expanded=False):
                    st.code(parsed.get("body_html"), language="html")

        with col_hdr:
            st.markdown("#### Parsed Message Headers")
            if parsed.get("headers"):
                st.json(parsed.get("headers"), expanded=True)
            else:
                st.caption("No RFC 822 structured headers available in pasted plaintext.")

    # --- TAB 6: Export Forensic Report ---
    with tab_export:
        st.markdown("### 📋 Export Forensic Security Audit Report")
        
        # Build Markdown Report
        markdown_report = f"""# Phishing Forensic Security Audit Report
**Generated by Antigravity Phishing Email Detective**

## 1. Executive Summary
- **Overall Phishing Risk Score:** {risk['score']} / 100
- **Threat Classification:** {risk['verdict']}
- **Summary:** {risk['summary']}

## 2. Header & Sender Alignment
- **From:** {parsed.get('from_header')}
- **From Domain:** {parsed.get('from_domain')}
- **Reply-To:** {parsed.get('reply_to_header')}
- **Reply-To Domain:** {parsed.get('reply_to_domain')}
- **Subject:** {parsed.get('subject')}
- **Header Risk Score:** +{sender_analysis['risk_score']} pts

## 3. Link & URL Forensics ({len(urls)} URLs inspected)
"""
        for u in urls:
            markdown_report += f"- URL: `{u['url']}` (Host: `{u['hostname']}`)\n"
            if u['display_text']:
                markdown_report += f"  - Anchor Text: `{u['display_text']}`\n"
            if u['flags']:
                markdown_report += f"  - Flags: {', '.join(u['flags'])}\n"
            markdown_report += f"  - Risk Points: +{u['risk_contribution']} pts\n"

        markdown_report += f"""
## 4. Urgency & Coercion Keywords
- Total Triggers: {urgency['total_found_count']}
- Keyword Risk Points: +{urgency['total_keyword_risk']} pts
"""
        for cat_name, cat_data in urgency.get("categories", {}).items():
            markdown_report += f"### {cat_name}\n"
            for m in cat_data.get("matches", []):
                markdown_report += f"- `{m['keyword']}` (Count: {m['count']})\n"

        markdown_report += f"""
## 5. Threat Vector Contribution
- Sender & Headers: {risk['breakdown']['Sender & Headers']} pts
- Links & URLs: {risk['breakdown']['Links & URLs']} pts
- Urgency Keywords: {risk['breakdown']['Urgency & Psychological Coercion']} pts
- Attachments: {risk['breakdown']['Attachments']} pts
- Subject / Structure: {risk['breakdown']['Subject / Structure']} pts
"""

        # JSON Export Data
        json_report = json.dumps({
            "score": risk["score"],
            "verdict": risk["verdict"],
            "summary": risk["summary"],
            "breakdown": risk["breakdown"],
            "parsed_email": {
                "from": parsed.get("from_header"),
                "from_domain": parsed.get("from_domain"),
                "reply_to": parsed.get("reply_to_header"),
                "reply_to_domain": parsed.get("reply_to_domain"),
                "subject": parsed.get("subject"),
                "date": parsed.get("date")
            },
            "header_analysis": sender_analysis,
            "url_analysis": urls,
            "urgency_analysis": urgency,
            "attachment_analysis": attachment_analysis
        }, indent=2)

        st.download_button(
            label="📥 Download Markdown Audit Report (.md)",
            data=markdown_report,
            file_name="phishing_forensic_report.md",
            mime="text/markdown"
        )
        st.download_button(
            label="📥 Download JSON Forensic Data (.json)",
            data=json_report,
            file_name="phishing_forensic_report.json",
            mime="application/json"
        )
        st.text_area("Report Preview (Markdown)", value=markdown_report, height=280)

else:
    # Initial state before analysis
    st.info("👆 Paste an email, upload a `.eml` file, or select a pre-loaded demonstration sample, then click **🔍 Analyze Email**.")
