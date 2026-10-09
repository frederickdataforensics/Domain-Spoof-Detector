import unittest
from types import SimpleNamespace
from unittest.mock import patch
from result_summary import summarize_result
from threat_intelligence import ThreatIntelligenceFinding
from app import create_app


def finding(status):
    return ThreatIntelligenceFinding(source='WhoisXML API', status=status,
        classification='none', match_type='hostname' if status == 'listed' else 'none',
        verified=False, detail='Source-reported result.')


class SummaryTests(unittest.TestCase):
    def test_priority_across_evidence_combinations(self):
        for indicators in (False, True):
            for statuses in ([], ['not_found'], ['unavailable'], ['listed'], ['listed', 'unavailable']):
                with self.subTest(indicators=indicators, statuses=statuses):
                    report = SimpleNamespace(findings=['sign'] if indicators else [], verdict='high risk')
                    summary = summarize_result(report, [finding(s) for s in statuses])
                    if 'listed' in statuses:
                        self.assertEqual(summary['title'], 'Warning: a threat record was found')
                        self.assertTrue(summary['avoid_link'])
                    elif indicators:
                        self.assertIn('look-alike', summary['title'])
                    elif 'unavailable' in statuses:
                        self.assertIn('incomplete', summary['title'])
                    else:
                        self.assertIn('No warning signs found', summary['title'])
                    self.assertNotIn('Low', summary['title'])

    def test_real_match_overrides_low_spelling_result_on_page(self):
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML': 'true'}):
            app = create_app()
        with patch('whoisxml_lookup.WhoisXMLClient.lookup', return_value=finding('listed')):
            body = app.test_client().post('/analyze', data={
                'value':'apple.appleidil.com','trusted':'apple.com','acknowledged':'yes'}).get_data(as_text=True)
        self.assertIn('Warning: a threat record was found', body)
        self.assertIn('Do not use this link.', body)
        self.assertIn('appleidil[.]com', body)
        self.assertNotIn('Low impersonation concern', body)
        self.assertLess(body.index('What you should do'), body.index('What supports this result'))

    def test_test_data_is_labeled(self):
        report = SimpleNamespace(findings=[], verdict='low risk')
        self.assertTrue(summarize_result(report, [finding('listed')], test_data=True)['title'].startswith('Test warning'))
