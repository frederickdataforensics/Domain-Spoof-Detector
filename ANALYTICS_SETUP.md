# FDF checker analytics setup

Measurement ID: `G-45BCG2QEE8` (public, not a secret).
Canonical page: `https://domain-spoof-detector-834650413835.europe-west1.run.app/`.

## 1. Finish the Google Analytics stream settings FIRST

1. Open Analytics > Admin > Data streams.
2. Select **FDF Suspicious Domain Checker**, ID `G-45BCG2QEE8`.
3. Turn **Enhanced measurement OFF for this entire stream** and save.
   This replaces the earlier recommendation to leave page views and scrolls on.
   Our code sends its own sanitized page views. Google documents that automatic
   history-based page views can still fire even with `send_page_view: false`.
4. Do not add a second Google tag, Google Tag Manager container, automatic
   form tracking, site-search tracking, user-provided-data collection, or Ads
   destination to this checker without another privacy review.
5. Leave the FDF business website's existing stream/tag alone.

## 2. Upload the files on the development branch

Use the `feature/domain-reputation` branch, then merge a pull request into `main`
after tests pass. If that branch contains unmerged unrelated work or is behind,
use a new `feature/checker-analytics` branch created from current `main` instead.
Do not overwrite a newer main revision with this whole historical source archive.
This update is based on the uploaded archive at commit
`93f7013e61d49403edc7fde56bfd7ac6d61b4099`.

Changed/new files and their exact destinations:

| Destination | Purpose |
| --- | --- |
| `app.py` | Analytics disable switch and narrow Google-tag CSP permissions |
| `templates/index.html` | Local script, generic status, disclosure, opt-out and FDF links |
| `static/analytics.js` | Sanitized GA4 metadata and bounded interaction events |
| `tests/test_analytics.py` | Flask integration and analytics checks |
| `tests/test_analytics.js` | Event payload and opt-out/privacy-signal checks |
| `ANALYTICS_SETUP.md` | These instructions |

After extracting the changed-files ZIP:

1. In GitHub, select your development branch in the branch dropdown.
2. At the repository root, upload `app.py` and `ANALYTICS_SETUP.md`.
   Suggested commit: `Add checker analytics configuration and setup guide`.
3. Open `templates/` on that SAME branch. Upload `index.html`.
   Suggested commit: `Add analytics controls and disclosure to checker page`.
4. Open `static/` on that SAME branch. Upload `analytics.js`.
   Suggested commit: `Track checker actions with sanitized GA4 metadata`.
5. Open `tests/` on that SAME branch. Upload BOTH test files.
   Suggested commit: `Test analytics privacy controls and event payloads`.
6. Create a pull request into `main`, wait for checks and review the diff.
7. Merge when checks pass. Confirm that the Cloud Run deployment for
   `domain-spoof-detector` in `europe-west1` completes successfully using your
   existing deployment process. GitHub upload alone does not prove deployment.

No API-key file, Secret Manager change or new dependency is needed.
The measurement ID is already in `static/analytics.js`.
Set Cloud Run environment variable `FDF_ENABLE_ANALYTICS=false` to disable
analytics globally if needed. When absent, this update enables it.

## 3. Verify the deployed tool

1. Open the checker in a browser without an analytics-blocking extension.
2. Check that the new disclosure and Allow usage analytics checkbox appear
   in the footer. If absent, verify the deployed revision before continuing.
3. In Analytics, open Realtime and confirm events in the checker stream.
4. Submit `paypa1.com` compared with `paypal.com` and accept the limitations.
   Verify `check_submitted` and `check_completed`; the normal analysis must work.
5. Click the FDF logo or footer homepage link. Look for `fdf_website_click`.
6. To exercise a displayed validation error, submit an invalid domain such as
   `not a valid domain` (the browser may block empty required fields before a
   submission occurs). Look for `check_failed` after the error page renders.
7. Uncheck Allow usage analytics. Reload and check another domain. The checker
   should still work, and the local analytics script should not load Google's
   tag for that browser. DNT/GPC signals also disable tracking.
8. Optionally use browser developer tools > Network, filter `collect`, and check
   that analytics payloads use the fixed checker page and title and do not
   contain submitted domains, paths, query values, fragments or comparison data.
   Test with harmless fabricated values; do not use real private links.

Realtime is useful for initial validation; standard reports can take longer.
Analytics is best effort. Ad blockers, disabled JavaScript, privacy signals,
visitor opt-out and requests lost during navigation can reduce counts.

## 4. What the events mean

| Event | Meaning |
| --- | --- |
| `page_view` | A checker page was rendered with tracking allowed |
| `check_submitted` | Browser submitted the checker form (not proof of a completed check) |
| `check_completed` | An analysis result page was rendered (not proof every intelligence provider responded) |
| `check_failed` | A displayed analysis/validation error page was rendered |
| `fdf_website_click` | Visitor clicked the logo or footer homepage link |

Optional event dimensions to register under Admin > Custom definitions,
if you need them in standard reports:

- `entry_source`: event-scoped; name `Checker entry source`.
- `link_placement`: event-scoped; name `FDF link placement`.
- `failure_kind`: event-scoped; name `Checker error type`.

`entry_source` has only `direct_or_unknown`, `fdf_or_google_sites`, or
`other_referral`. Actual referring URLs and their arbitrary hostnames are not
sent. Google Sites referrals are grouped together; this does not prove every
such referral came from FDF. Accurate campaign/search attribution is deliberately
limited by stripped page/referrer metadata. Do not claim it measures all sources.

Use reports filtered by this stream (Stream ID/name as available) or the fixed
checker hostname. Do not confuse FDF website traffic with checker traffic.
If marking `fdf_website_click` as a key event, label it as website interest,
not a consultation, sale or confirmed lead.

Page refreshes/resubmitted POST pages can repeat completed/failed counts.
These events are page interactions, not unique cases or a reliable failure-rate
denominator. Transport failures or unhandled server errors without a rendered
checker page are not measured by this browser instrumentation.

## 5. Privacy behavior and scope

The first-party analytics code never reads form values, reports or error text.
It sets fixed page location/title, blank referrer, and only allowlisted event
labels and bounded metadata. Google Signals and ad personalization are disabled.
This is not anonymous analytics: Google still processes normal device,
connection, cookie and analytics identifiers. Previously transmitted events are
not deleted by the browser opt-out. If browser storage is blocked, a preference
may not persist to the next page. The checker works without analytics.

The footer links to your existing Privacy, Storage and Data Integrity page.
Reconcile that page and the terms under attorney review with this actual use of
Google Analytics. No website policy or legal agreement was edited in this ZIP.
No changes were made to threat feeds, API credentials, scoring, homoglyph checks,
typosquatting, mixed-script detection or customer recommendations.

## Sources

Checked October 13, 2026:
- Google page views: https://developers.google.com/analytics/devguides/collection/ga4/views
- Google privacy settings: https://developers.google.com/tag-platform/security/guides/privacy
- Enhanced measurement: https://support.google.com/analytics/answer/9216061

## Tests

Run from the repository root:
```
python -m unittest discover -s tests -v
node tests/test_analytics.js
```
The Python suite invokes the JavaScript tests when Node is available.
