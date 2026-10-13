/* Only fixed event labels and canonical page metadata go to GA4.
 * Never read input values, results, query strings, fragments or error text.
 * Disable ALL enhanced measurement on this stream before deployment.
 */
(() => {
  'use strict';
  const measurementId = 'G-45BCG2QEE8';
  const canonicalPage = 'https://domain-spoof-detector-834650413835.europe-west1.run.app/';
  const preferenceKey = 'fdf_usage_analytics';
  const control = document.getElementById('usage-analytics');
  const status = document.getElementById('analytics-preference');
  const privacySignal = navigator.globalPrivacyControl === true ||
    navigator.doNotTrack === '1' || window.doNotTrack === '1';
  let allowed = !privacySignal;
  try { allowed = allowed && localStorage.getItem(preferenceKey) !== 'off'; }
  catch (_) { /* Storage can be unavailable in an embedded/private browser. */ }
  let initialized = false;
  const disabledKey = 'ga-disable-' + measurementId;
  window[disabledKey] = !allowed;

  // Classify the entry source without sending the referring URL or hostname.
  let entrySource = 'direct_or_unknown';
  if (document.referrer) {
    try {
      const host = new URL(document.referrer).hostname;
      entrySource = ['www.frederickdataforensics.net', 'frederickdataforensics.net',
        'sites.google.com'].includes(host) ? 'fdf_or_google_sites' : 'other_referral';
    } catch (_) { /* Do not send malformed referrer strings. */ }
  }
  const safePage = {
    page_location: canonicalPage,
    page_referrer: '',
    page_title: 'FDF Suspicious Domain Checker',
    send_to: measurementId,
  };
  function event(name, extra = {}) {
    if (allowed && typeof window.gtag === 'function') {
      window.gtag('event', name, { ...safePage, ...extra });
    }
  }
  function initialize() {
    if (initialized) return;
    initialized = true;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    // Set privacy-safe page values before configuration and tag loading.
    window.gtag('set', {
      page_location: canonicalPage,
      page_referrer: '',
      page_title: safePage.page_title,
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
    });
    window.gtag('js', new Date());
    window.gtag('config', measurementId, {
      ...safePage,
      send_page_view: false,
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
    });
    event('page_view', { entry_source: entrySource });
    const result = document.body.dataset.checkStatus;
    if (result === 'completed') event('check_completed');
    if (result === 'failed') event('check_failed', { failure_kind: 'displayed_error' });
    const tag = document.createElement('script');
    tag.async = true;
    tag.referrerPolicy = 'no-referrer';
    tag.src = 'https://www.googletagmanager.com/gtag/js?id=' + measurementId;
    document.head.appendChild(tag);
  }
  function updatePreference() {
    if (control) { control.checked = allowed; control.disabled = privacySignal; }
    if (status) status.textContent = privacySignal ?
      'Usage analytics is off because this browser requests privacy.' : allowed ?
      'Usage analytics is allowed. The checker also works with analytics off.' :
      'Usage analytics is off on this browser.';
  }
  if (control) control.addEventListener('change', () => {
    allowed = control.checked && !privacySignal;
    window[disabledKey] = !allowed;
    try { localStorage.setItem(preferenceKey, allowed ? 'on' : 'off'); }
    catch (_) { /* Current-page opt-out still works without storage. */ }
    updatePreference();
    if (allowed) initialize();
  });
  updatePreference();
  if (allowed) initialize();
  const form = document.querySelector('.checker-form');
  if (form) form.addEventListener('submit', () => event('check_submitted'));
  document.querySelectorAll('[data-fdf-link]').forEach(link => {
    link.addEventListener('click', () => {
      const placement = link.dataset.fdfLink;
      if (placement === 'logo' || placement === 'footer') {
        event('fdf_website_click', { link_placement: placement });
      }
    });
  });
})();
