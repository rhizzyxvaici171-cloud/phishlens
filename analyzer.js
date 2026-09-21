/**
 * PhishLens core analysis engine.
 *
 * Every function here is pure: given a URL string, return findings. No DOM,
 * no network calls, nothing that can't run identically in a browser or in
 * a plain Node test script. That's deliberate: it's what makes this whole
 * thing checkable without literally clicking a malicious link to see what
 * happens.
 */

// A short list of frequently-spoofed brand names. Not exhaustive by
// design, this is meant to catch the common cases (paypa1.com,
// arnazon.com) rather than replicate a full threat-intel feed.
const WATCHED_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "instagram", "netflix", "whatsapp", "linkedin", "twitter", "tiktok",
  "ebay", "coinbase", "binance", "wellsfargo", "chase", "dhl", "fedex",
  "ups", "dropbox", "adobe", "yahoo", "outlook",
];

// TLDs that see disproportionate use in phishing/spam campaigns, either
// because they're free/cheap to register or because they're new enough
// that filters haven't caught up. Presence alone isn't proof of anything.
const WATCHED_TLDS = new Set([
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work",
  "click", "link", "country", "kim", "review", "loan", "download",
]);

const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
]);

// A short list of two-part TLDs, so the "registrable domain" guess (used
// to compare against subdomain labels) isn't fooled by things like
// "co.uk" or "com.ng" into treating the second-to-last label as the
// whole story. Not a full public-suffix-list implementation, just enough
// to handle the common cases without dragging in a dependency.
const TWO_PART_TLDS = new Set([
  "co.uk", "co.za", "co.ke", "co.in", "com.ng", "com.au", "com.br",
  "com.cn", "com.mx", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.sg",
]);

const SEVERITY_WEIGHT = { critical: 40, high: 25, medium: 12, low: 5 };

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function isIPv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIPv6(host) {
  return host.includes(":") && /^[0-9a-fA-F:]+$/.test(host);
}

function registrableDomain(hostname) {
  const labels = hostname.split(".");
  if (labels.length < 2) return hostname;
  const lastTwo = labels.slice(-2).join(".");
  if (TWO_PART_TLDS.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

function hasMixedScript(label) {
  const hasLatin = /[a-zA-Z]/.test(label);
  const hasCyrillic = /[\u0400-\u04FF]/.test(label);
  const hasGreek = /[\u0370-\u03FF]/.test(label);
  return hasLatin && (hasCyrillic || hasGreek);
}

/**
 * The main entry point. Takes whatever the person typed or pasted and
 * returns { ok, error } on failure, or a full analysis on success.
 */
function analyzeUrl(rawInput) {
  const input = (rawInput || "").trim();
  if (!input) {
    return { ok: false, error: "Paste a URL to check." };
  }

  // The classic @ trick: everything before an unencoded @ is userinfo
  // and browsers silently ignore it, so "https://paypal.com@evil.ru/"
  // actually goes to evil.ru, not paypal.com. Must be checked on the
  // RAW string, since URL parsing itself will have already resolved it
  // away and we'd never see it.
  const hasAtTrick = /^[a-z]+:\/\/[^/]*@/i.test(input) && /^[a-z]+:\/\/[^/@]*[a-zA-Z][^/@]*@/i.test(input);

  let urlObj;
  let hadNoProtocol = false;
  try {
    urlObj = new URL(input);
  } catch (e) {
    try {
      urlObj = new URL("http://" + input);
      hadNoProtocol = true;
    } catch (e2) {
      return { ok: false, error: "That doesn't look like a valid URL." };
    }
  }

  // Browsers are far more lenient than this check needs to be: Chrome
  // happily accepts "http://not a url" by percent-encoding the spaces
  // into the hostname itself ("not%20a%20url"), rather than rejecting
  // it. A real DNS hostname never legitimately contains a percent-encoded
  // character, so this catches garbage input that technically "parses"
  // but was never a real URL to begin with.
  if (urlObj.hostname.includes("%") || !/^[a-z0-9.\-:\[\]]+$/i.test(urlObj.hostname)) {
    return { ok: false, error: "That doesn't look like a valid URL." };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const labels = hostname.split(".");
  const findings = [];

  if (hasAtTrick) {
    findings.push({
      severity: "critical",
      title: "Contains an \"@\" before the real host",
      detail: "Browsers ignore everything before an unencoded \"@\" in a URL. The text that looks like the destination may not be where this link actually goes.",
    });
  }

  if (isIPv4(hostname) || isIPv6(hostname)) {
    findings.push({
      severity: "high",
      title: "Uses a raw IP address instead of a domain name",
      detail: "Legitimate services almost always use a named domain. A bare IP address is a common way to avoid domain-based blocklists.",
    });
  }

  if (labels.some(l => l.startsWith("xn--"))) {
    findings.push({
      severity: "high",
      title: "Contains an encoded international domain (punycode)",
      detail: "This domain includes non-ASCII characters encoded as \"xn--...\". It may display as different-looking (even identical-looking) characters in a browser's address bar than what's shown here. Verify very carefully before trusting it.",
    });
  }

  const mixedScriptLabel = labels.find(hasMixedScript);
  if (mixedScriptLabel) {
    findings.push({
      severity: "high",
      title: "Mixes different alphabets in one domain label",
      detail: `The label "${mixedScriptLabel}" mixes Latin letters with Cyrillic or Greek characters that can look nearly identical (a classic homograph attack, e.g. a Cyrillic "а" instead of a Latin "a").`,
    });
  }

  // Brand-lookalike checks, run against every label in the hostname.
  const registrable = registrableDomain(hostname);
  const registrableBase = registrable.split(".")[0];
  let brandFlagged = false;
  for (const label of labels) {
    if (brandFlagged) break;
    for (const brand of WATCHED_BRANDS) {
      if (label === brand) continue; // exact match to the brand itself is fine
      const dist = levenshtein(label, brand);
      const closeEnough = dist > 0 && dist <= 2 && Math.abs(label.length - brand.length) <= 2 && label.length >= 4;
      if (closeEnough) {
        findings.push({
          severity: "critical",
          title: `Looks like a misspelled version of "${brand}"`,
          detail: `The label "${label}" is very close to "${brand}" but not an exact match, a common trick (e.g. "paypa1" instead of "paypal").`,
        });
        brandFlagged = true;
        break;
      }
    }
  }
  // Separately: a brand name appearing as a subdomain while the actual
  // registrable domain is something unrelated (e.g.
  // "paypal.com.verify-login.info"), a very common phishing pattern.
  if (!brandFlagged) {
    for (const brand of WATCHED_BRANDS) {
      const brandIsRegistrable = registrableBase === brand;
      const brandAppearsElsewhere = labels.slice(0, -2).some(l => l === brand);
      if (!brandIsRegistrable && brandAppearsElsewhere) {
        findings.push({
          severity: "critical",
          title: `"${brand}" appears in the address, but isn't the real domain`,
          detail: `The actual domain being visited is "${registrable}". "${brand}" showing up earlier in the address doesn't mean it's affiliated. Only the part immediately before the TLD (the registrable domain) tells you who really controls this site.`,
        });
        brandFlagged = true;
        break;
      }
    }
  }
  // A third pattern, arguably the most common of all in the wild: the
  // brand name glued directly into the registrable domain alongside
  // other words ("paypal-secure-login.com", "amazon-support.net").
  // Different from the lookalike check above, this isn't a misspelling,
  // the brand name is spelled correctly but padded with extra text.
  if (!brandFlagged) {
    for (const brand of WATCHED_BRANDS) {
      if (registrableBase === brand) continue; // the real thing
      if (registrableBase.includes(brand) && registrableBase.length > brand.length) {
        findings.push({
          severity: "critical",
          title: `"${brand}" is embedded in a longer, unrelated domain`,
          detail: `The domain is "${registrable}", not "${brand}.com" or similar. Padding a real brand name with extra words like "secure", "support", or "login" is one of the most common phishing domain patterns, it's spelled correctly specifically to avoid typo-detection.`,
        });
        brandFlagged = true;
        break;
      }
    }
  }

  if (KNOWN_SHORTENERS.has(hostname)) {
    findings.push({
      severity: "medium",
      title: "This is a link-shortening service",
      detail: "The real destination is hidden until the link is followed. Expand it with a preview tool first, or ask the sender for the full URL.",
    });
  }

  const tld = labels[labels.length - 1];
  if (WATCHED_TLDS.has(tld)) {
    findings.push({
      severity: "medium",
      title: `Uses a ".${tld}" domain`,
      detail: `".${tld}" sees disproportionate use in phishing and spam campaigns, often because it's cheap or new. Not proof of anything by itself, just worth extra scrutiny.`,
    });
  }

  if (urlObj.protocol !== "https:") {
    findings.push({
      severity: "medium",
      title: "Not using HTTPS",
      detail: "This connection isn't encrypted. Never enter a password, card number, or other sensitive information on a plain http:// page.",
    });
  }

  if (urlObj.port && !["80", "443", ""].includes(urlObj.port)) {
    findings.push({
      severity: "low",
      title: `Uses a non-standard port (${urlObj.port})`,
      detail: "Most legitimate consumer-facing sites use the default web ports. A custom port isn't inherently malicious, but it's unusual for something like a login page.",
    });
  }

  const subdomainDepth = labels.length - registrable.split(".").length;
  if (subdomainDepth >= 3) {
    findings.push({
      severity: "low",
      title: "Unusually deep subdomain chain",
      detail: `${subdomainDepth} subdomain levels before reaching "${registrable}". Long chains are sometimes used to push the real domain out of a truncated address bar view.`,
    });
  }

  if (input.length > 120) {
    findings.push({
      severity: "low",
      title: "Very long URL",
      detail: "Long URLs with many parameters aren't inherently suspicious (tracking links do this constantly), but they're also harder to visually verify.",
    });
  }

  if (hadNoProtocol) {
    findings.push({
      severity: "low",
      title: "No protocol specified",
      detail: "Assumed http:// to check this. Always confirm which protocol a real link actually uses.",
    });
  }

  const score = Math.min(100, findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0));
  let level = "low";
  if (score >= 70) level = "critical";
  else if (score >= 40) level = "high";
  else if (score >= 15) level = "medium";

  // A single critical-severity finding (the @ trick, a brand lookalike)
  // is dangerous enough on its own that it shouldn't get diluted into
  // "high" just because the additive score happens to land under the
  // critical threshold. The worst individual finding sets a floor.
  const severityOrder = ["low", "medium", "high", "critical"];
  const worstFinding = findings.reduce(
    (worst, f) => severityOrder.indexOf(f.severity) > severityOrder.indexOf(worst) ? f.severity : worst,
    "low"
  );
  if (severityOrder.indexOf(worstFinding) > severityOrder.indexOf(level)) {
    level = worstFinding;
  }

  return {
    ok: true,
    hostname,
    registrable,
    protocol: urlObj.protocol,
    findings,
    score,
    level,
  };
}

// Allow this file to be loaded both as a browser <script> and as a plain
// Node module for testing, without needing a bundler either way.
if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyzeUrl, levenshtein, isIPv4, isIPv6, registrableDomain, hasMixedScript };
}
