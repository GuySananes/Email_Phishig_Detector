// Code.gs — Gmail Add-on: Email Phishing Detector

// ─── Entry Points ────────────────────────────────────────────────────────────

/**
 * Called when the add-on is opened from the Gmail contextual trigger.
 * Builds the sidebar card shown when viewing an email.
 */
function buildAddOn(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId   = e.messageMetadata.messageId;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  var sender  = message.getFrom();
  var body    = message.getPlainBody();
  var subject = message.getSubject();
  var fullText = "From: " + sender + "\nSubject: " + subject + "\n\n" + body;

  return buildResultCard(fullText, sender, subject);
}

/**
 * Homepage card — shown when the add-on is opened outside of a message.
 */
function buildHomePage() {
  var card    = CardService.newCardBuilder();
  var section = CardService.newCardSection();

  section.addWidget(
    CardService.newTextParagraph().setText(
      "📧 <b>Phishing Detector</b><br><br>" +
      "Open any email and this add-on will automatically scan it for phishing indicators.<br><br>" +
      "Checks performed:<br>" +
      "• Spoofed sender domain<br>" +
      "• Urgent / manipulative language<br>" +
      "• Suspicious or IP-based URLs"
    )
  );

  card.addSection(section);
  return card.build();
}


// ─── Core Card Builder ───────────────────────────────────────────────────────

function buildResultCard(fullText, sender, subject) {
  var result = analyzeEmail(fullText, sender);

  var card    = CardService.newCardBuilder();
  var header  = CardService.newCardHeader()
    .setTitle("Phishing Detector 🎣")
    .setSubtitle("Subject: " + subject);
  card.setHeader(header);

  // ── Verdict section ──
  var verdictSection = CardService.newCardSection().setHeader("Verdict");

  var verdictText, verdictIcon;
  if (result.score >= 3) {
    verdictText = "🚨 LIKELY PHISHING";
    verdictIcon = "Do NOT click links or reply to this email.";
  } else if (result.score > 0) {
    verdictText = "⚠️ SUSPICIOUS EMAIL";
    verdictIcon = "Proceed with caution — unusual elements found.";
  } else {
    verdictText = "✅ LOOKS SAFE";
    verdictIcon = "No common phishing indicators detected.";
  }

  verdictSection.addWidget(
    CardService.newTextParagraph().setText(
      "<b>" + verdictText + "</b><br>" + verdictIcon
    )
  );
  verdictSection.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Phishing Score")
      .setContent(String(result.score))
  );
  card.addSection(verdictSection);

  // ── Indicators section ──
  if (result.indicators.length > 0) {
    var indicatorsSection = CardService.newCardSection().setHeader("Detected Indicators");
    for (var i = 0; i < result.indicators.length; i++) {
      indicatorsSection.addWidget(
        CardService.newTextParagraph().setText("• " + result.indicators[i])
      );
    }
    card.addSection(indicatorsSection);
  }

  return [card.build()];
}


// ─── Detection Logic ─────────────────────────────────────────────────────────

/**
 * Orchestrates all detectors and returns { score, indicators }.
 */
function analyzeEmail(fullText, senderRaw) {
  var score      = 0;
  var indicators = [];

  // 1. Sender spoofing
  var senderEmail = extractSenderEmail(senderRaw);
  if (senderEmail) {
    var spoofWarning = analyzeSender(senderEmail);
    if (spoofWarning) {
      score += 2;
      indicators.push("Spoofed Sender (+2): " + spoofWarning);
    }
  }

  // 2. Urgent language
  var urgentPhrases = detectUrgentLanguage(fullText);
  if (urgentPhrases.length > 0) {
    score += 1;
    indicators.push("Urgent Language (+1): " + urgentPhrases.join(", "));
  }

  // 3. Suspicious URLs
  var urls          = extractUrls(fullText);
  var suspiciousUrls = [];
  for (var i = 0; i < urls.length; i++) {
    var reasons = analyzeUrl(urls[i]);
    if (reasons.length > 0) {
      suspiciousUrls.push(urls[i] + " (" + reasons.join(", ") + ")");
    }
  }
  if (suspiciousUrls.length > 0) {
    score += 2;
    indicators.push("Suspicious Links (+2): " + suspiciousUrls.length + " bad link(s) found.");
    for (var j = 0; j < suspiciousUrls.length; j++) {
      indicators.push("  → " + suspiciousUrls[j]);
    }
  }

  return { score: score, indicators: indicators };
}

// ── Sender helpers ────────────────────────────────────────────────────────────

/**
 * Extracts the raw email address from a "Display Name <email>" string.
 */
function extractSenderEmail(from) {
  var match = from.match(/<([^>]+)>/);
  if (match) return match[1].toLowerCase();
  var plain = from.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
  return plain ? plain[0].toLowerCase() : null;
}

/**
 * Checks the sender domain against trusted domains using similarity scoring.
 */
function analyzeSender(email) {
  var trustedDomains = ["paypal.com", "amazon.com", "google.com", "microsoft.com", "upwind.io"];
  var parts = email.split("@");
  if (parts.length < 2) return "Invalid email format";

  var domain = parts[1].toLowerCase();
  if (trustedDomains.indexOf(domain) !== -1) return null;

  for (var i = 0; i < trustedDomains.length; i++) {
    var similarity = stringSimilarity(domain, trustedDomains[i]);
    if (similarity >= 0.8 && similarity < 1.0) {
      return "'" + domain + "' is suspiciously similar to '" + trustedDomains[i] + "'";
    }
  }
  return null;
}

/**
 * Simple Levenshtein-based similarity ratio (mirrors Python's difflib.SequenceMatcher).
 */
function stringSimilarity(a, b) {
  var longer  = a.length > b.length ? a : b;
  var shorter = a.length > b.length ? b : a;
  if (longer.length === 0) return 1.0;
  return (longer.length - editDistance(longer, shorter)) / longer.length;
}

function editDistance(s1, s2) {
  var costs = [];
  for (var i = 0; i <= s1.length; i++) {
    var lastValue = i;
    for (var j = 0; j <= s2.length; j++) {
      if (i === 0) {
        costs[j] = j;
      } else if (j > 0) {
        var newValue = costs[j - 1];
        if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
          newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
        }
        costs[j - 1] = lastValue;
        lastValue = newValue;
      }
    }
    if (i > 0) costs[s2.length] = lastValue;
  }
  return costs[s2.length];
}

// ── Urgent language ───────────────────────────────────────────────────────────

function detectUrgentLanguage(text) {
  var keywords = ["urgent", "immediately", "action required", "verify now", "account suspended"];
  var lower    = text.toLowerCase();
  var found    = [];
  for (var i = 0; i < keywords.length; i++) {
    if (lower.indexOf(keywords[i]) !== -1) found.push(keywords[i]);
  }
  return found;
}

// ── URL helpers ───────────────────────────────────────────────────────────────

function extractUrls(text) {
  var pattern = /https?:\/\/[^\s<>"]+/g;
  return text.match(pattern) || [];
}

function analyzeUrl(url) {
  var reasons = [];

  var domain = "";
  try {
    var match = url.match(/^https?:\/\/([^\/\?#]+)/);
    domain = match ? match[1].toLowerCase() : "";
  } catch (e) {
    return ["Invalid URL format"];
  }

  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(domain)) {
    reasons.push("IP address used instead of domain");
  }
  if ((domain.match(/-/g) || []).length > 2) {
    reasons.push("Multiple hyphens in domain");
  }
  if (domain.indexOf("paypa1") !== -1) {
    reasons.push("Brand spoofing detected (looks like 'paypal')");
  }
  if (url.length > 80) {
    reasons.push("URL is suspiciously long");
  }

  return reasons;
}