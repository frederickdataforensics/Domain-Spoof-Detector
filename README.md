
A Python command-line tool that detects IDN homograph attacks, Unicode confusables, mixed-script domains, and ASCII typosquatting through code-point analysis and trusted-domain comparison.
# Domain Spoof Detector

Domain Spoof Detector is a Python command-line tool designed to identify potential domain-impersonation techniques used in phishing, credential theft, social engineering, and other malicious activity. It analyzes a URL or hostname without connecting to it and reports characteristics that may indicate an Internationalized Domain Name (IDN) homograph attack, Unicode homoglyph attack, or ASCII-based typosquatting attempt.

The repository also includes an optional Flask web interface suitable for a
standalone deployment or embedding in Google Sites. See
[`WEB_DEPLOYMENT.md`](WEB_DEPLOYMENT.md) for local testing, privacy behavior,
Cloud Run deployment, and embedding instructions.

The tool examines the actual characters underlying a hostname rather than relying only on how the domain appears visually. For non-ASCII and other notable characters, it can report the character’s position, Unicode code point, official Unicode name, writing system, and corresponding visual skeleton. This makes it possible to distinguish visually similar characters such as the ASCII Latin `a` (`U+0061`) and Cyrillic `а` (`U+0430`).

[![Use the Web-Based Tool](https://img.shields.io/badge/Use%20the%20Web--Based%20Tool-0078B8?style=for-the-badge)](https://domain-spoof-detector-834650413835.europe-west1.run.app/)

Use the hosted checker without installing Python:  
[Open the FDF Domain Spoof Detector](https://domain-spoof-detector-834650413835.europe-west1.run.app/)

## Features

* Extracts hostnames from plain domain names and complete URLs
* Performs analysis without visiting or connecting to the supplied address
* Detects Punycode labels beginning with `xn--`
* Converts between Unicode and ASCII/Punycode hostname representations
* Identifies non-ASCII characters within domain names
* Examines the Unicode code point and official name of notable characters
* Detects multiple writing systems used within the same domain label
* Builds visual skeletons using the Unicode Consortium’s confusables dataset
* Compares suspicious domains against explicitly supplied trusted domains
* Detects common ASCII look-alike substitutions, such as `1` for `l` and `0` for `o`
* Detects multi-character look-alikes, such as `rn` resembling `m`
* Detects adjacent-character transpositions
* Detects character insertions and omissions using Levenshtein distance
* Detects hyphen insertion or removal
* Assigns a heuristic risk score and overall verdict
* Supports human-readable and JSON-formatted output
* Supports comparison against multiple trusted domains

## Detection Categories

### IDN and Punycode Detection

Internationalized Domain Names allow Unicode characters to appear in domain names. Their DNS-compatible representation uses Punycode and commonly begins with the `xn--` prefix.

The presence of Punycode is not inherently malicious. Many legitimate websites use internationalized domain names. However, Punycode can conceal characters that resemble letters in a trusted domain, so the tool decodes these labels for further examination.

### Unicode Homoglyph Detection

A homoglyph is a character that visually resembles another character. Attackers can combine characters from different writing systems to create a domain that appears legitimate to a human reader.

For example:

```text
paypal.com
pаypal.com
```

These domains appear similar, but the second domain contains a Cyrillic `а`:

```text
ASCII a:    U+0061 LATIN SMALL LETTER A
Cyrillic а: U+0430 CYRILLIC SMALL LETTER A
```

Domain Spoof Detector exposes this underlying character information and compares the domain’s visual skeleton against trusted domains.

### Mixed-Script Detection

The program identifies domain labels containing characters from multiple writing systems. For example, a single label containing both Latin and Cyrillic letters may warrant further investigation.

Mixed-script analysis is performed at the individual label level. This avoids automatically treating a domain as mixed-script merely because its internationalized name uses a Latin top-level domain such as `.com`.

### ASCII Typosquatting Detection

Domain impersonation does not require Unicode. Attackers can register ASCII-only domains that exploit common typing mistakes or visual similarities.

The tool checks trusted-domain comparisons for techniques including:

* Character substitution: `paypa1.com` versus `paypal.com`
* Character omission: `paypa.com`
* Character insertion: `paypall.com`
* Adjacent transposition: `payapl.com`
* Hyphen manipulation: `pay-pal.com`
* Sequence substitution: `rn` resembling `m`

These checks require at least one trusted domain because digits, hyphens, and similar spellings are not inherently suspicious without a meaningful comparison target.

## Unicode Confusables Data

The detector uses the Unicode Consortium’s `confusables.txt` dataset to create visual skeletons for comparison. The included dataset is based on Unicode 17.0.0 and contains thousands of mappings between visually confusable characters.

Unicode Technical Standard #39 defines mechanisms for detecting potential security problems involving Unicode identifiers:

* https://www.unicode.org/reports/tr39/
* https://www.unicode.org/Public/17.0.0/security/confusables.txt

The project uses this dataset as one component of its detection logic. It should not be interpreted as a claim of complete conformance with every requirement of Unicode Technical Standard #39.

## Requirements

* Python 3.10 or later
* `confusables.txt` located in the same directory as the Python script

The program uses Python’s standard library and does not require additional third-party Python packages.


## Repository Structure

```text
domain-spoof-detector/
├── .github/
│   └── workflows/
│       └── tests.yml
├── LICENSES/
│   └── UNICODE-LICENSE-V3.txt
├── data/
│   └── fabricated_threat_feed.json
├── static/
│   ├── FDF-brand-image-320x132-email-logo.png
│   └── styles.css
├── templates/
│   └── index.html
├── tests/
│   └── [automated tests and test fixtures]
├── .dockerignore
├── .gitignore
├── Dockerfile
├── LICENSE
├── Quick Start for Everyday Users.md
├── README.md
├── THIRD_PARTY_NOTICES.md
├── TRADEMARKS.md
├── Technical Usage.md
├── WEB_DEPLOYMENT.md
├── app.py
├── confusables.txt
├── idnHomoglyphDetector.py
├── local_threat_lookup.py
├── phishtank_feed.py
├── requirements.txt
├── threat_intelligence.py
└── update_phishtank_feed.py
```
## Usage

General syntax:


python3 idnHomoglyphDetector.py VALUE [--trusted DOMAIN] [--json]


Display help:

```powershell
python3 .\idnHomoglyphDetector.py --help
```

Analyze a hostname:

```powershell
python3 .\idnHomoglyphDetector.py example.com
```

Compare a suspected typosquatting domain with a trusted domain:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com
```

Analyze a Punycode hostname:

```powershell
python3 .\idnHomoglyphDetector.py xn--80ak6aa92e.com --trusted apple.com
```

Analyze a Unicode hostname:

```powershell
python3 .\idnHomoglyphDetector.py "pаypal.com" --trusted paypal.com
```

Request JSON output:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com --json
```

Save JSON output to a file:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com --json > results.json
```

Compare against multiple trusted domains:

```powershell
python3 .\idnHomoglyphDetector.py suspicious-domain.com `
    --trusted paypal.com `
    --trusted apple.com `
    --trusted microsoft.com
```

## Understanding the Results

The checker reports indicators found in the submitted domain name. It does not open the destination or determine by itself whether a website, link, sender, or organization is safe or malicious.

### Domain-Name Analysis

The report may include:

- The extracted hostname, displayed in a sanitized or defanged form
- The decoded Unicode representation
- The ASCII or Punycode representation
- Writing systems detected, such as Latin or Cyrillic
- Mixed-script or look-alike-character indicators
- A computed visual skeleton used to compare characters that may look alike
- Character-level Unicode evidence
- Comparison with an expected legitimate domain, when one is provided
- Individual findings and severity levels
- A domain-indicator score
- An overall domain-name assessment

A **visual skeleton** is a simplified comparison form that helps identify characters with a similar appearance. It is an analytical value and is not another version of the actual domain.

The domain-indicator score is not a percentage probability that a domain is malicious. It summarizes only the indicators supported by the checks implemented in this tool.

### Domain-Name Assessments

- **No supported indicators detected:** The implemented checks did not identify supported domain-name warning signs using the information provided.
- **Supported indicators detected:** One or more domain-name characteristics warrant additional review.
- **Strong impersonation indicators detected:** Strong visual-similarity or trusted-domain impersonation indicators were identified.

A result with no supported indicators does not establish that a domain is safe. A strong-indicator result does not independently prove malicious ownership, intent, or activity.

Providing the expected legitimate domain allows the checker to perform a stronger spelling and visual comparison. Without it, certain ASCII substitutions or brand-impersonation patterns may not be detectable.

### Known-Phishing Intelligence

When an approved phishing-intelligence source is configured and successfully queried, the report may also identify:

- The intelligence source checked
- Whether an exact submitted-URL match was found
- Whether a hostname match was found
- The source or feed update time
- Whether the lookup returned a match, no match, was unavailable, or encountered an error

A phishing-intelligence match means that the submitted URL or hostname appears in the identified source. It does not mean that Frederick Data Forensics independently verified every aspect of the listing.

A “not found” result means only that no matching record was located in the intelligence data available to the tool at the time of analysis. It does not establish that the URL, domain, sender, or destination is safe.

The public phishing-intelligence feature remains under development until an approved live data source is configured and tested.

### Defanged Addresses

A defanged address has been changed slightly—for example, `example.com` becomes `example[.]com`—to reduce the chance that it will be opened accidentally or treated as a clickable link.

Defanging does not change the address being analyzed, prove that the address is harmful, or make the original destination safe.

## Intended Use

This project is intended for:

* Cybersecurity education
* Digital-forensics and incident-response training
* Phishing triage
* Suspicious-link analysis
* Domain-brand monitoring
* Security research
* Demonstrating Unicode and IDN security concepts

The detector performs static string analysis only. It does not conduct DNS resolution, WHOIS or RDAP queries, certificate inspection, reputation checks, webpage retrieval, or malware analysis.

## Limitations

* Detection is heuristic and may produce false positives or false negatives.
* Legitimate internationalized domains may contain Unicode or multiple scripts.
* Visual similarity depends partly on the font and rendering environment.
* Trusted-domain comparison is only as complete as the trusted domains supplied by the user.
* Levenshtein distance identifies textual similarity but does not prove impersonation.
* The Unicode confusables dataset may change between Unicode versions.
* The tool does not determine domain ownership, registration intent, reputation, or malicious activity.
* The tool does not replace browser protections, threat-intelligence services, or analyst review.
* Unicode script detection in this project is simplified and does not implement the complete Unicode Script_Extensions algorithm.
* The current tool analyzes one investigation target per execution.

## Security and Privacy

The tool does not navigate to, retrieve content from, or otherwise contact the supplied hostname. Analysis is performed locally on the input string and the locally stored Unicode confusables dataset.

Users should still avoid opening suspicious URLs in a normal browser or resolving potentially malicious domains from sensitive systems.

## Future Development

Possible future improvements include:

* Batch analysis from text, CSV, or JSON files
* Pipeline input through standard input
* Trusted-domain lists loaded from files
* RDAP and domain-registration analysis
* DNS and certificate inspection
* Domain-age and reputation checks
* Public-suffix-aware domain comparison
* Expanded script-property analysis
* Exportable HTML or CSV reports
* Automated unit tests
* SIEM or SOAR integration
* Configurable scoring policies

## Trademark and Branding Notice

The software code in this repository is provided under the license identified in the [`LICENSE`](LICENSE) file.

“Frederick Data Forensics,” “FDF,” and the Frederick Data Forensics logo are trademarks, service identifiers, or brand assets of Frederick Data Forensics, L.L.C. The software license does not grant permission to use this branding to imply affiliation, endorsement, or that a modified deployment is an official Frederick Data Forensics service.

Modified or redistributed versions should remove Frederick Data Forensics branding unless prior written permission has been granted. Required copyright, license, attribution, and third-party notices must still be retained.

See [`TRADEMARKS.md`](TRADEMARKS.md) for the complete brand-use policy.

## License

The Python source code is licensed under the MIT License. See `LICENSE`.

The included Unicode confusables dataset is provided by Unicode, Inc. under the Unicode License v3. See `THIRD_PARTY_NOTICES.md` and the licensing information contained in `confusables.txt`.

## Disclaimer

This software is provided for educational, defensive-security, and research purposes. Its findings should be treated as indicators requiring analyst interpretation, not as conclusive determinations that a domain is safe or malicious.

## Known-Threat Intelligence Development Status

The project includes a local threat-intelligence lookup framework that is
currently intended for development and testing. It remains separate from the
domain-name character and spelling analysis.

The intelligence framework does not visit, resolve, or connect to submitted
domains or URLs. Lookups are performed against locally stored records. Full
submitted URLs are processed only as necessary for comparison, while public
results display a sanitized, defanged hostname.

### Fabricated Test Feed

The repository includes a small fabricated feed containing reserved
`.example.test` domains. These records are fictional and exist only to test:

- Exact-URL matches
- Hostname associations
- No-match results
- Unavailable-feed results
- Threat-category separation
- Safe display and defanging behavior

The fabricated feed must never be described as real threat intelligence or
used to make decisions about actual domains.

### Feature Flag

The fabricated lookup is disabled by default. It runs only when the following
environment variable is explicitly enabled:

```text
FDF_ENABLE_FABRICATED_THREAT_FEED=true
```
## PhishTank Feed Integration

The application supports local lookups against a validated PhishTank JSON
feed. Submitted URLs are compared locally; the application does not visit,
resolve, or connect to destinations contained in either user input or the
feed.

The feed updater:

- Connects only to the approved PhishTank HTTPS data host
- Restricts redirects to that same host
- Limits compressed and decompressed file sizes
- Rejects empty, malformed, or inactive-only feeds
- Validates the complete replacement before activation
- Preserves the last valid feed when an update fails

The application distinguishes exact URL matches from hostname associations.
A hostname association does not establish that the submitted URL itself
appears in the feed. A no-match result does not establish safety.

### Runtime configuration

The updater writes to the path configured by:

```text
FDF_PHISHTANK_DESTINATION
