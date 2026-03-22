import argparse
from utils import load_email
import detectors


def calculate_and_print_report(email_text):
    """
    Orchestrates the detection modules, calculates the score, and prints the report.
    """
    phishing_score = 0
    indicators_found = []

    # 1. Analyze Sender
    sender_email = detectors.extract_sender(email_text)
    if sender_email:
        spoof_warning = detectors.analyze_sender(sender_email)
        if spoof_warning:
            phishing_score += 2
            indicators_found.append(f"[+2] Spoofed Sender: {spoof_warning}")

    # 2. Analyze Urgent Language
    urgent_phrases = detectors.detect_urgent_language(email_text)
    if urgent_phrases:
        phishing_score += 1
        indicators_found.append(f"[+1] Urgent Language: {', '.join(urgent_phrases)}")

    # 3. Analyze Links
    extracted_urls = detectors.extract_urls(email_text)
    suspicious_links_found = []

    if extracted_urls:
        for url in extracted_urls:
            reasons = detectors.analyze_url(url)
            if reasons:
                suspicious_links_found.append(f"{url} ({', '.join(reasons)})")

    if suspicious_links_found:
        phishing_score += 2
        indicators_found.append(f"[+2] Suspicious Links ({len(suspicious_links_found)} found):")
        for bad_link in suspicious_links_found:
            indicators_found.append(f"     - {bad_link}")

    # --- Print Final Summary Report ---
    print("\n==================================================")
    print("             EMAIL ANALYSIS REPORT                ")
    print("==================================================")
    print(f"Total Phishing Score: {phishing_score}\n")

    if phishing_score >= 3:
        print("VERDICT: [!] LIKELY PHISHING ATTEMPT [!]")
        print("Recommendation: Do not click any links or reply to this email.\n")
    elif phishing_score > 0:
        print("VERDICT: [-] SUSPICIOUS EMAIL [-]")
        print("Recommendation: Proceed with caution. Some unusual elements were found.\n")
    else:
        print("VERDICT: [V] LOOKS SAFE [V]")
        print("Recommendation: No common phishing indicators were detected.\n")

    if indicators_found:
        print("Detailed Indicators:")
        for indicator in indicators_found:
            print(indicator)
    print("==================================================")


def main():
    # Set up the command line argument parser
    parser = argparse.ArgumentParser(description="Scan an email file for phishing indicators.")
    parser.add_argument("file", help="Path to the email text file to scan")
    args = parser.parse_args()

    print(f"--- Loading email from: {args.file} ---")
    email_text = load_email(args.file)

    if email_text:
        calculate_and_print_report(email_text)


if __name__ == "__main__":
    main()