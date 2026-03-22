# Email Phishing Detector 🎣

A tool that scans email content for common phishing indicators and alerts the user to potential threats.

## Features

- **Spoofed sender detection** — flags domains that look similar to trusted ones (PayPal, Google, etc.)
- **Urgent language detection** — catches manipulative keywords like "urgent", "verify now", "account suspended"
- **Suspicious URL analysis** — detects IP-based URLs, excessive hyphens, brand spoofing, and overly long links
- **Phishing score** — combines all signals into a single risk score with a clear verdict

## Project Structure

```
Email_Phishing_Detector/
├── app.py              # Streamlit web UI
├── main.py             # CLI entry point
├── detectors.py        # Core detection logic
├── utils.py            # File reading helper
├── sample_email.txt    # Example phishing email for testing
├── gmail_addon/
│   ├── Code.gs         # Gmail Add-on (Google Apps Script)
│   └── appsscript.json # Add-on manifest
├── requirements.txt
└── .gitignore
```

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
git clone https://github.com/GuySananes/Email_Phishig_Detector.git
cd Email_Phishig_Detector
pip install -r requirements.txt
```

### Run the Streamlit UI

```bash
streamlit run app.py
```

Then open your browser at `http://localhost:8501`, upload a `.txt` email file, and click **Scan Email**.

### Run the CLI

```bash
python main.py sample_email.txt
```

## Gmail Add-on Setup

The add-on runs entirely inside Google Apps Script — no server required.

1. Go to [script.google.com](https://script.google.com) and create a new project
2. Copy the contents of `gmail_addon/Code.gs` into the editor
3. Replace the default `appsscript.json` (via **Project Settings → Show manifest**) with `gmail_addon/appsscript.json`
4. Click **Deploy → Test deployments → Install** to install it in your Gmail
5. Open any email in Gmail — the add-on sidebar will appear automatically and scan the email

## Detection Logic

| Indicator | Score |
|---|---|
| Spoofed sender domain | +2 |
| Urgent / manipulative language | +1 |
| Suspicious URLs | +2 |

| Total Score | Verdict |
|---|---|
| 0 | ✅ Looks Safe |
| 1–2 | ⚠️ Suspicious |
| 3+ | 🚨 Likely Phishing |

## Sample Output (CLI)

```
==================================================
             EMAIL ANALYSIS REPORT
==================================================
Total Phishing Score: 5

VERDICT: [!] LIKELY PHISHING ATTEMPT [!]
Recommendation: Do not click any links or reply to this email.

Detailed Indicators:
[+2] Spoofed Sender: 'paypa1.com' is suspiciously similar to 'paypal.com'
[+1] Urgent Language: urgent, immediately, action required, verify now, account suspended
[+2] Suspicious Links (2 found):
     - http://192.168.1.10/login (IP address used instead of a domain name)
     - http://paypa1-security-login.com (Multiple hyphens in domain, Brand spoofing detected)
==================================================
```