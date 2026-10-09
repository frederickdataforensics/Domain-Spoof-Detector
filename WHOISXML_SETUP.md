# WhoisXML integration setup

This update adds server-side, exact-hostname WhoisXML Threat Intelligence API lookups.
No full URL, path, query string, fragment, or embedded credentials are sent.
The submitted destination is never visited. Results are separate from the domain-name score.

## Files to update in GitHub

- app.py
- templates/index.html
- static/styles.css
- whoisxml_lookup.py (new)
- tests/test_whoisxml_lookup.py (new)
- tests/test_detector.py (updated UI assertions)
- WHOISXML_SETUP.md (new)

No new Python dependencies are required. Never commit an API key or .env file.

## Stage and configure

1. Apply these files to the existing private development branch and deploy to the
   separate Cloud Run staging service first. Keep the public production service unchanged.
2. In Google Cloud Secret Manager, create a secret named `whoisxml-api-key` and
   paste your key there. Give the staging service's runtime service account
   Secret Manager Secret Accessor permission on that secret only.
3. In the staging Cloud Run service's revision settings, reference that secret
   as environment variable `WHOISXML_API_KEY` (pin a secret version).
4. Add ordinary environment variable `FDF_ENABLE_WHOISXML=true` to staging.
   Without this flag no WhoisXML requests are made, even if a key is present.
5. Deploy the staging revision. Test example.com, a Unicode hostname, and a URL
   with a harmless dummy query. Confirm only the hostname appears in results.
6. Confirm customer-facing usage rights with WhoisXML before enabling the public
   service. Repeat the secret and flag configuration on production when ready.

## Credit controls and limits

Each fresh query requests at most 100 records, costing at most one credit under
WhoisXML's current documented request rules. The default cache lasts 15 minutes;
cached results retain their original lookup timestamp. Errors are not cached.
Each Python worker permits 10 outbound attempts per rolling hour. Failed attempts
also count toward this local cap. No automatic retries or wildcard searches occur.

IMPORTANT: these controls are per worker, reset on restart, and are not a global
spending guarantee. The current Dockerfile runs two workers, so one instance can
make up to 20 attempts/hour. Autoscaling adds more independent caps. Before broad
public access, use a shared quota counter/API gateway and provider-side spend or
credit limits if available. Do not rely on a Google Cloud billing budget to cap
third-party WhoisXML credits. Keep trial testing restricted to staging.

Missing keys, timeouts, provider errors, malformed responses and unexpected
matches display 'Threat lookup unavailable', never 'No matching records'.
Positive results are reported as source associations, without independently
claiming verification or that a website is malicious. Raw provider records are
not displayed. Turn off `FDF_ENABLE_WHOISXML` to disable the feature immediately.

Documentation:
https://threat-intelligence.whoisxmlapi.com/api/documentation/making-requests
https://threat-intelligence.whoisxmlapi.com/api/documentation/output-format
