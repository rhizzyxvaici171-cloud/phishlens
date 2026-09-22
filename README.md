# PhishLens 🔍

A URL phishing inspector that runs entirely in the browser. Paste a link, and it checks the URL text itself for patterns commonly used in phishing and social-engineering attacks, before you ever click it.

**[Live demo](https://rhizzyxvaici171-cloud.github.io/phishlens)**

## What it detects

- **The "@" trick**: everything before an unencoded `@` in a URL is ignored by the browser, so `https://accounts.google.com@evil-site.ru/` actually goes to `evil-site.ru`, not Google. Checked on the raw input, since URL parsing itself would already have resolved this away by the time you could inspect it.
- **Brand lookalikes**: domains a short edit-distance away from a real brand name, like `paypa1.com`.
- **Brand embedding**: a real brand name spelled correctly but padded into an unrelated domain, like `paypal-secure-login.com` or `amazon-support.net`, arguably the most common phishing domain pattern of all, specifically because it's spelled correctly enough to dodge typo-based detection.
- **Brand-name-as-subdomain**: a trusted name appearing earlier in the address while the actual registrable domain is something else entirely, like `paypal.com.verify-account.info`.
- **Punycode and mixed-script domains**: encoded international domains, or domains mixing Latin letters with visually similar Cyrillic or Greek characters (a classic homograph attack).
- **Raw IP addresses** used instead of a domain name.
- **Known link shorteners**, where the real destination is hidden until the link is followed.
- **Commonly abused TLDs**, non-standard ports, missing HTTPS, unusually deep subdomain chains, and a few other lower-severity signals.

## What it deliberately doesn't do

This is a pattern check on the URL text itself, nothing more. It does not visit the link, scan for malware, check domain reputation databases, or confirm a site's actual identity. A clean result isn't a guarantee of safety, and a flagged result isn't proof of malicious intent, it's a prompt to look closer, not a verdict.

## Tech

Plain HTML, CSS, and JavaScript. No dependencies, no build step, no backend, and no network calls of any kind, everything happens locally in the browser. The detection logic (`analyzer.js`) is written as pure functions with no DOM dependency, so it can also be loaded and tested directly in Node.

## Running it locally

```bash
git clone https://github.com/rhizzyxvaici171-cloud/phishlens.git
cd phishlens
open index.html
```

## Testing the detection logic

```bash
node -e "
const { analyzeUrl } = require('./analyzer.js');
console.log(analyzeUrl('https://paypal-secure-login.com/'));
"
```

## Deploying to GitHub Pages

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Source**, select the `main` branch and `/ (root)` folder, then Save.
4. Live at `https://rhizzyxvaici171-cloud.github.io/phishlens/` shortly after.

## A bug worth mentioning

During testing, garbage input like `"not a url"` was silently accepted as valid in the browser, while correctly rejected in Node. Chrome's URL parser turned out to be more lenient than Node's: it percent-encodes invalid characters like spaces directly into the hostname (`"not a url"` became the hostname `"not%20a%20url"`) rather than rejecting the input outright. Since a real DNS hostname never legitimately contains a percent-encoded character, the fix checks for that specifically, catching exactly the class of input that technically "parses" but was never a real URL to begin with.

## Project structure

```
phishlens/
├── index.html
├── style.css
├── analyzer.js    # pure detection logic, DOM-free and independently testable
├── script.js      # UI wiring
├── README.md
└── LICENSE
```

## License

MIT, see [LICENSE](LICENSE).
