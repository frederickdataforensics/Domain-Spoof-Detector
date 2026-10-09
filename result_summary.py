"""Combine evidence into one customer-facing message without declaring safety."""
def summarize_result(report, findings, *, test_data=False):
    listed = any(f.status == 'listed' for f in findings)
    incomplete = any(f.status == 'unavailable' for f in findings)
    indicators = bool(report.findings)
    if listed:
        return {
            'level': 'high',
            'title': 'Warning: a threat record was found' if not test_data else 'Test warning: a threat record was found',
            'message': 'A checked source reports a threat record associated with this address. Treat the link cautiously. This record does not independently prove that the website is currently malicious.' if not test_data else 'A source returned a listing while development test data is enabled. Review the source below; fabricated records are not real threat evidence.',
            'avoid_link': True,
        }
    if any(getattr(f, 'reason', None) == 'Misleading trusted name in subdomain' for f in report.findings):
        return {'level': 'high', 'title': 'Warning: this is not the expected website domain',
                'message': 'The expected website name appears at the beginning of an address under a different domain. That name placement can be misleading; it does not prove malicious intent.',
                'avoid_link': True}
    if indicators:
        return {'level': 'high' if report.verdict == 'high risk' else 'moderate',
                'title': 'Warning: this domain has look-alike signs',
                'message': 'The address contains character or spelling signs that deserve caution. These signs alone do not prove that a website is malicious.',
                'avoid_link': True}
    if incomplete:
        return {'level': 'moderate', 'title': 'Check incomplete: verify the link another way',
                'message': 'The threat-record check could not be completed. The spelling checks found no warning signs, but the link has not been cleared as safe.',
                'avoid_link': False}
    return {'level': 'neutral', 'title': 'No warning signs found in the checks performed',
            'message': 'These checks did not find warning signs. They cannot confirm that the link is safe. Verify the address through the organization before using it.' if findings else 'The domain-name checks did not find warning signs. Threat intelligence was not checked. Verify the address through the organization before using it.',
            'avoid_link': False}
