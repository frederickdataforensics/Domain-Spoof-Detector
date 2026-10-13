import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from app import create_app


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        with patch.dict(os.environ, {"FDF_ENABLE_ANALYTICS": "true", "FDF_ENABLE_WHOISXML": "false"}):
            self.app = create_app()
        self.client = self.app.test_client()

    def test_server_exposes_only_generic_status_for_analytics(self):
        response = self.client.post('/analyze', data={
            'value': 'https://paypa1.com/private?token=private-secret#private',
            'trusted': 'paypal.com', 'acknowledged': 'yes',
        })
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-check-status="completed"', body)
        self.assertNotIn('private-secret', body)
        self.assertIn('Character 6', body)
        self.assertIn('analytics.js', body)
        failed = self.client.post('/analyze', data={'value': ''})
        self.assertEqual(failed.status_code, 400)
        self.assertIn('data-check-status="failed"', failed.get_data(as_text=True))
        self.assertIn('data-check-status="none"', self.client.get('/').get_data(as_text=True))

    def test_tag_is_external_and_csp_does_not_allow_inline_scripts(self):
        response = self.client.get('/')
        csp = response.headers['Content-Security-Policy']
        self.assertIn("script-src 'self' https://www.googletagmanager.com", csp)
        self.assertNotIn('unsafe-inline', csp)
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('googletagmanager.com/gtag', response.get_data(as_text=True))

    def test_server_disable_switch_does_not_change_analysis(self):
        with patch.dict(os.environ, {'FDF_ENABLE_ANALYTICS': 'false'}):
            app = create_app()
        response = app.test_client().post('/analyze', data={'value': 'paypa1.com', 'trusted': 'paypal.com', 'acknowledged': 'yes'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('analytics.js', response.get_data(as_text=True))
        self.assertIn('Character 6', response.get_data(as_text=True))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for browser-script tests')
    def test_browser_events_and_privacy_controls(self):
        subprocess.run(['node', str(Path(__file__).with_suffix('.js'))], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
