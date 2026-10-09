import unittest
from unittest.mock import patch
from app import create_app
from whoisxml_lookup import parse_response


class IntelligenceDisplayTests(unittest.TestCase):
    def test_provider_metadata_is_preserved(self):
        result = parse_response({'total': 2, 'results': [
            {'iocType':'domain','value':'example.com','threatType':'phishing','lastSeen':'2026-10-09T15:00:00Z'},
            {'iocType':'domain','value':'example.com','threatType':'malware','lastSeen':'2026-10-08T15:00:00Z'},
        ]}, 'example.com')
        self.assertEqual(result.classification, 'malware, phishing')
        self.assertEqual(result.source_timestamp, '2026-10-09T15:00:00+00:00')
        self.assertFalse(result.verified)

    def test_dates_and_types_are_not_invented(self):
        for date in (None, 'invalid', '2026-10-09T12:00:00'):
            result = parse_response({'total':1,'results':[
                {'iocType':'domain','value':'example.com','lastSeen':date,'threatType':'unexpected'}
            ]}, 'example.com')
            self.assertIsNone(result.source_timestamp)
            self.assertEqual(result.classification, 'unspecified')

    def test_eastern_time_has_dst_labels_and_date_rollover(self):
        formatter = create_app().jinja_env.filters['eastern_time']
        self.assertEqual(formatter('2026-10-09T17:01:00Z'), 'Oct 09, 2026 at 01:01 PM US Eastern Time (EDT, UTC-04:00)')
        self.assertEqual(formatter('2026-01-09T17:01:00Z'), 'Jan 09, 2026 at 12:01 PM US Eastern Time (EST, UTC-05:00)')
        self.assertEqual(formatter('2026-10-09T02:00:00Z'), 'Oct 08, 2026 at 10:00 PM US Eastern Time (EDT, UTC-04:00)')
        self.assertEqual(formatter('invalid'), 'Date unavailable')

    def test_page_displays_real_category_without_false_verification(self):
        finding = parse_response({'total':1,'results':[
            {'iocType':'domain','value':'example.com','threatType':'phishing','lastSeen':'2026-10-08T15:00:00Z'}
        ]}, 'example.com')
        with patch.dict('os.environ', {'FDF_ENABLE_WHOISXML':'true'}):
            app=create_app()
        with patch('whoisxml_lookup.WhoisXMLClient.lookup',return_value=finding):
            body=app.test_client().post('/analyze',data={'value':'example.com','acknowledged':'yes'}).get_data(as_text=True)
        self.assertIn('Phishing (fake messages or websites used to steal information)',body)
        self.assertIn('Most recent observation reported by provider',body)
        self.assertIn('US Eastern Time (EDT, UTC-04:00)',body)
        self.assertNotIn('Not verified',body)
        self.assertNotIn('Source verification',body)
        self.assertNotIn('Not provided',body)
        self.assertNotIn('Source Reported',body)
