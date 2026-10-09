import unittest
from unittest.mock import patch
from domain_structure import domain_parts, misleading_subdomain
from idnHomoglyphDetector import analyze
from app import create_app


class DomainStructureTests(unittest.TestCase):
    def test_real_apple_example(self):
        report = analyze('apple.appleidil.com', ['apple.com'])
        self.assertEqual(report.verdict, 'high risk')
        self.assertTrue(any(f.reason == 'Misleading trusted name in subdomain' for f in report.findings))
        self.assertEqual(domain_parts(report.ascii_hostname)['domain'], 'appleidil.com')

    def test_embedded_full_trusted_domain(self):
        self.assertEqual(misleading_subdomain('usps.com.delivery-confirmation.com', 'usps.com'), 'delivery-confirmation.com')
        self.assertEqual(misleading_subdomain('usps.com.delivery-confirmation.test', 'usps.com'), 'delivery-confirmation.test')
        self.assertEqual(misleading_subdomain('login.apple.com.account-check.net', 'apple.com'), 'account-check.net')

    def test_legitimate_subdomains_and_label_boundaries(self):
        for host in ('apple.com', 'login.apple.com', 'support.login.apple.com'):
            self.assertIsNone(misleading_subdomain(host, 'apple.com'))
        self.assertIsNone(misleading_subdomain('pineapple.example.com', 'apple.com'))
        self.assertIsNone(misleading_subdomain('apple.news.apple.com', 'apple.com'))
        self.assertIsNone(misleading_subdomain('apple.com', 'login.apple.com'))

    def test_country_suffixes(self):
        self.assertEqual(domain_parts('login.bbc.co.uk')['domain'], 'bbc.co.uk')
        self.assertIsNone(misleading_subdomain('news.bbc.co.uk', 'bbc.co.uk'))
        self.assertEqual(misleading_subdomain('bbc.co.uk.check-example.com', 'bbc.co.uk'), 'check-example.com')

    def test_private_hosting_boundaries(self):
        self.assertEqual(domain_parts('apple.attacker.github.io')['domain'], 'attacker.github.io')
        self.assertEqual(misleading_subdomain('apple.attacker.github.io', 'apple.com'), 'attacker.github.io')
        self.assertIsNone(misleading_subdomain('docs.customer.github.io', 'customer.github.io'))

    def test_unknown_suffix_and_ip_do_not_invent_domain(self):
        self.assertIsNone(domain_parts('192.0.2.1')['domain'])
        self.assertIsNone(domain_parts('apple.somewhere.invalid')['domain'])
        self.assertIsNone(misleading_subdomain('apple.somewhere.invalid','apple.com'))

    def test_no_network_for_domain_structure(self):
        with patch('requests.sessions.Session.request', side_effect=AssertionError('Network forbidden')):
            self.assertEqual(domain_parts('bbc.co.uk')['domain'], 'bbc.co.uk')
            analyze('apple.appleidil.com', ['apple.com'])

    def test_existing_checks_still_find_their_indicators(self):
        cases = [
            ('paypa1.com', 'paypal.com', 'ASCII look-alike substitution'),
            ('payapl.com', 'paypal.com', 'Adjacent-character transposition'),
            ('paypol.com', 'paypal.com', 'ASCII typosquatting similarity'),
            ('pay-pal.com', 'paypal.com', 'Hyphen manipulation'),
            ('раypal.com', 'paypal.com', 'Mixed writing systems within a label'),
            ('раypal.com', 'paypal.com', 'ASCII-like homoglyphs'),
            ('xn--ypal-43d9g.com', 'paypal.com', 'Punycode label'),
        ]
        for host, trusted, reason in cases:
            with self.subTest(host=host, reason=reason):
                self.assertIn(reason, [f.reason for f in analyze(host, [trusted]).findings])

    def test_page_warns_with_intelligence_disabled(self):
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML': ''}):
            app = create_app()
        body = app.test_client().post('/analyze', data={
            'value': 'apple.appleidil.com', 'trusted': 'apple.com', 'acknowledged': 'yes'}).get_data(as_text=True)
        self.assertIn('Warning: this is not the expected website domain', body)
        self.assertIn('appleidil[.]com', body)
        self.assertIn('Do not use this link.', body)
        self.assertNotIn('Low impersonation concern', body)
