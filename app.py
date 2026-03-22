# app.py
import streamlit as st
import detectors


def main():
    st.set_page_config(page_title="Phishing Detector", page_icon="🎣")
    st.title("Email Phishing Detector 🎣")
    st.write("Welcome to the Phishing Scanner. Let's catch some bad emails!")

    st.subheader("Upload an Email")
    uploaded_file = st.file_uploader("Choose a text file containing the email", type=["txt"])

    if uploaded_file is not None:
        email_content = uploaded_file.getvalue().decode("utf-8")

        # We put the raw text inside an expander so it doesn't clutter the screen
        with st.expander("View Raw Email Content"):
            st.text_area("", email_content, height=200)

        # --- Stage 3 & 4: The Scan Button & Results Area ---
        st.markdown("---")

        # Add a prominent scan button
        if st.button("🔍 Scan Email", type="primary"):
            st.subheader("Analysis Results")

            # Show a cool spinning animation while it "scans"
            with st.spinner("Analyzing headers, links, and language..."):

                phishing_score = 0
                indicators_found = []

                # 1. Analyze Sender
                sender_email = detectors.extract_sender(email_content)
                if sender_email:
                    spoof_warning = detectors.analyze_sender(sender_email)
                    if spoof_warning:
                        phishing_score += 2
                        indicators_found.append(f"**Spoofed Sender (+2)**: {spoof_warning}")

                # 2. Analyze Urgent Language
                urgent_phrases = detectors.detect_urgent_language(email_content)
                if urgent_phrases:
                    phishing_score += 1
                    indicators_found.append(f"**Urgent Language (+1)**: {', '.join(urgent_phrases)}")

                # 3. Analyze Links
                extracted_urls = detectors.extract_urls(email_content)
                suspicious_links_found = []

                if extracted_urls:
                    for url in extracted_urls:
                        reasons = detectors.analyze_url(url)
                        if reasons:
                            suspicious_links_found.append(f"{url} ({', '.join(reasons)})")

                if suspicious_links_found:
                    phishing_score += 2
                    indicators_found.append(
                        f"**Suspicious Links (+2)**: Found {len(suspicious_links_found)} bad link(s).")
                    for bad_link in suspicious_links_found:
                        # Add a bullet point for each bad link
                        indicators_found.append(f" - {bad_link}")

                # --- Display the Final Verdict ---

                # Big bold metric for the score
                st.metric(label="Total Phishing Score", value=phishing_score)

                # Colored alert boxes based on the score threshold
                if phishing_score >= 3:
                    st.error(
                        "🚨 **VERDICT: LIKELY PHISHING ATTEMPT** 🚨\n\nRecommendation: Do not click any links or reply to this email.")
                elif phishing_score > 0:
                    st.warning(
                        "⚠️ **VERDICT: SUSPICIOUS EMAIL** ⚠️\n\nRecommendation: Proceed with caution. Some unusual elements were found.")
                else:
                    st.success(
                        "✅ **VERDICT: LOOKS SAFE** ✅\n\nRecommendation: No common phishing indicators were detected.")

                # --- Display Detailed Indicators ---
                if indicators_found:
                    st.write("### Detailed Indicators:")
                    for indicator in indicators_found:
                        st.write(indicator)


if __name__ == "__main__":
    main()