"""
Realistic Pre-Loaded Sample Emails for Quick Testing
Covers classic credential harvesting, CEO wire fraud (BEC), IT Helpdesk lures, and legitimate receipts.
"""

SAMPLE_PAYPAL_PHISHING = """From: "PayPal Account Security" <service@paypal.com>
Reply-To: support@paypal-verification-center.xyz
To: victim.user@company.com
Subject: URGENT: Your PayPal Account Has Been Suspended - Immediate Action Required
Date: Mon, 16 Nov 2026 09:15:32 -0400
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<head><title>Account Suspended</title></head>
<body style="font-family: Arial, sans-serif;">
  <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ccc; padding: 20px;">
    <h2 style="color: #c00;">Suspicious Activity Detected: Account Locked</h2>
    <p>Dear Customer,</p>
    <p>We detected an <strong>unauthorized access</strong> attempt to your PayPal account from an unrecognized IP address in Moscow, Russia.</p>
    <p>For your security, your account access has been restricted. <strong>Immediate action required:</strong> You must verify your account within 24 hours to prevent permanent account closure.</p>
    <p>Failure to validate your identity will result in all pending transactions being terminated immediately.</p>
    <p style="margin: 30px 0;">
      <!-- Notice: Display text claims to be legitimate PayPal, but href points to an IP/phishing destination -->
      <a href="http://192.168.1.105/paypal/signin.php?token=9384729" style="background-color: #0070ba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
        https://www.paypal.com/signin/verify-identity
      </a>
    </p>
    <p>Or alternatively visit our backup portal: <a href="http://paypal-account-safety.xyz/login">http://paypal-account-safety.xyz/login</a></p>
    <p>Please confirm your password and update billing information promptly.</p>
    <p>Sincerely,<br>PayPal Security & Risk Prevention Team</p>
  </div>
</body>
</html>
"""

SAMPLE_CEO_FRAUD = """From: "Robert Vance (CEO)" <ceo.office.robertvance@gmail.com>
Reply-To: corporate-treasury-desk@proton.me
To: jane.finance@company.com
Subject: URGENT: Confidential Wire Transfer Request - Act Now
Date: Mon, 16 Nov 2026 08:30:00 -0500
Content-Type: text/plain; charset="UTF-8"

Jane,

I am currently in an all-day executive board meeting with our external acquisition team and cannot take phone calls. 

We have a time-sensitive closing transaction for our new branch acquisition. I need you to process an immediate wire transfer of $48,500.00 to the escrow account provided below before 2:00 PM today.

This matter is strictly confidential until the official press release tomorrow. Do not discuss this with anyone in the office.

Please confirm receipt immediately and let me know when the wire transfer reference number is available.

Deadline is within 2 hours. Prompt attention required.

Robert Vance
Chief Executive Officer
Sent from my iPad
"""

SAMPLE_MICROSOFT_PASSWORD = """From: "IT Support Helpdesk" <admin-alerts@it-microsoft-support.top>
Reply-To: admin-alerts@it-microsoft-support.top
To: employee@organization.org
Subject: Security Alert: Your Office 365 Password Expires Today
Date: Mon, 16 Nov 2026 10:02:11 +0100
Content-Type: text/html; charset="UTF-8"

<html>
<body>
  <h3>Office 365 Security Department</h3>
  <p>Hello User,</p>
  <p>Your domain password for employee@organization.org is set to expire within 12 hours.</p>
  <p>To keep your current password and prevent email disruption, you must reset your password and validate your account using the single sign-on portal below:</p>
  <p>
    <!-- Shortened URL hiding destination -->
    <a href="https://bit.ly/m365-pass-renew">Click Here to Keep Current Password</a>
  </p>
  <p>If no action is taken before the deadline, your account will be locked and you will lose access to corporate emails and files.</p>
  <p>IT Department - Automated Notification Service</p>
</body>
</html>
"""

SAMPLE_LEGITIMATE_RECEIPT = """From: "GitHub" <noreply@github.com>
Reply-To: support@github.com
To: amey@developer.io
Subject: [GitHub] Payment Receipt for Invoice #GH-839210
Date: Mon, 16 Nov 2026 07:12:45 +0000
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
  <h2>GitHub Subscription Receipt</h2>
  <p>Hi Amey,</p>
  <p>Thank you for using GitHub. This email confirms payment for your GitHub Pro monthly subscription.</p>
  <ul>
    <li><strong>Invoice Number:</strong> GH-839210</li>
    <li><strong>Amount Charged:</strong> $4.00 USD</li>
    <li><strong>Date:</strong> November 16, 2026</li>
    <li><strong>Status:</strong> Paid</li>
  </ul>
  <p>You can review your billing history and download your PDF invoice anytime at: <a href="https://github.com/settings/billing">https://github.com/settings/billing</a></p>
  <p>If you have any questions, feel free to visit our documentation at <a href="https://docs.github.com/billing">https://docs.github.com/billing</a>.</p>
  <p>Cheers,<br>The GitHub Team</p>
</body>
</html>
"""

SAMPLES = {
    "🎣 Phishing: PayPal Credential Harvester (Mismatched Reply-To & Anchor)": SAMPLE_PAYPAL_PHISHING,
    "💼 BEC Scam: CEO Wire Fraud Impersonation (Free Webmail + Urgency)": SAMPLE_CEO_FRAUD,
    "🔑 Phishing: Microsoft 365 Password Expiration Alert (Shortened URL)": SAMPLE_MICROSOFT_PASSWORD,
    "🟢 Legitimate: Authentic GitHub Pro Billing Receipt": SAMPLE_LEGITIMATE_RECEIPT
}
