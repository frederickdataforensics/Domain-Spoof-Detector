import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from whoisxml_lookup import WhoisXMLClient, parse_response, NoRedirects


class WhoisXMLTests(unittest.TestCase):
    def client(self, payload, **kwargs):
        opener = Mock()
        response = Mock()
        response.__enter__ = Mock(side_effect=lambda: io.BytesIO(json.dumps(payload).encode()))
        response.__exit__ = Mock(return_value=False)
        opener.open.return_value = response
        return WhoisXMLClient('secret-test-key', opener=opener, **kwargs), opener

    def test_zero_records_and_cache(self):
        client, opener = self.client({'total': 0, 'results': []})
        first = client.lookup('example.com')
        self.assertEqual(first.status, 'not_found')
        self.assertEqual(client.lookup('example.com'), first)
        self.assertEqual(opener.open.call_count, 1)

    def test_positive_exact_domain(self):
        result = parse_response({'total': 1, 'results': [
            {'iocType': 'domain', 'value': 'example.com', 'threatType': 'phishing'}
        ]}, 'example.com')
        self.assertEqual(result.status, 'listed')
        self.assertFalse(result.verified)

    def test_bad_or_unrelated_responses_are_not_clean(self):
        for payload in ({'error': 'invalid key'}, {'total': 1, 'results': []},
                        {'total': 0, 'results': [{}]},
                        {'total': 1, 'results': [{'iocType': 'domain', 'value': 'other.com'}]}):
            client, _ = self.client(payload)
            self.assertEqual(client.lookup('example.com').status, 'unavailable')

    def test_timeout_does_not_leak_secret(self):
        client, opener = self.client({})
        opener.open.side_effect = TimeoutError('secret-test-key')
        finding = client.lookup('example.com')
        self.assertEqual(finding.status, 'unavailable')
        self.assertNotIn('secret-test-key', str(finding))

    def test_limit_and_expiry(self):
        clock = Mock(return_value=0)
        client, opener = self.client({'total': 0, 'results': []}, hourly_limit=1, clock=clock)
        client.lookup('example.com')
        self.assertEqual(client.lookup('other.com').status, 'unavailable')
        clock.return_value = 3601
        self.assertEqual(client.lookup('other.com').status, 'not_found')
        self.assertEqual(opener.open.call_count, 2)

    def test_missing_key_and_wildcards_never_call_provider(self):
        client, opener = self.client({})
        self.assertEqual(client.lookup('*.com').status, 'unavailable')
        client._api_key = ''
        self.assertEqual(client.lookup('example.com').status, 'unavailable')
        opener.open.assert_not_called()

    def test_redirects_refused(self):
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, '', {}, 'https://other.test'))

    def test_request_is_encoded_and_bounded(self):
        client, opener = self.client({'total': 0, 'results': []})
        client.lookup('example.com')
        args, kwargs = opener.open.call_args
        query = parse_qs(urlsplit(args[0].full_url).query)
        self.assertEqual(query['ioc'], ['example.com'])
        self.assertEqual(query['size'], ['100'])
        self.assertEqual(kwargs['timeout'], 5)

    def test_web_hostname_only_and_simple_results(self):
        from app import create_app
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML': 'true', 'WHOISXML_API_KEY': 'secret-test-key'}):
            app = create_app()
        finding = parse_response({'total': 0, 'results': []}, 'example.com')
        with patch('whoisxml_lookup.WhoisXMLClient.lookup', return_value=finding) as lookup:
            response = app.test_client().post('/analyze', data={
                'value': 'https://example.com/private?token=do-not-share', 'acknowledged': 'yes'})
        lookup.assert_called_once_with('example.com')
        body = response.get_data(as_text=True)
        self.assertIn('No matching threat records found', body)
        self.assertNotIn('do-not-share', body)
        self.assertNotIn('secret-test-key', body)

    def test_disabled_makes_no_lookup(self):
        from app import create_app
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML': ''}):
            app = create_app()
        with patch('whoisxml_lookup.WhoisXMLClient.lookup') as lookup:
            app.test_client().post('/analyze', data={'value': 'example.com', 'acknowledged': 'yes'})
        lookup.assert_not_called()

    def test_paypal_explanation_and_one_based_position(self):
        from app import create_app
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML': ''}):
            app = create_app()
        body = app.test_client().post('/analyze', data={
            'value': 'paypa1.com', 'trusted': 'paypal.com', 'acknowledged': 'yes'}).get_data(as_text=True)
        self.assertIn('High impersonation concern', body)
        self.assertIn('Character 6 is <code>1</code>', body)
        self.assertLess(body.index('What we found'), body.index('What you should do'))
        self.assertLess(body.index('What you should do'), body.index('Technical details'))
        self.assertIn('<summary>Technical details</summary>', body)


if __name__ == '__main__':
    unittest.main()
