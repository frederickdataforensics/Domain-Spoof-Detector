"""Offline domain-boundary parsing using the bundled Public Suffix List."""
from __future__ import annotations
import ipaddress
import tldextract

# Never fetch suffix data at runtime or contact the submitted destination.
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True,
    extra_suffixes=("test",),  # Reserved test names, for safe offline examples.
)


def domain_parts(hostname):
    hostname = hostname.lower().rstrip('.')
    try:
        ipaddress.ip_address(hostname.strip('[]'))
        return {'domain': None, 'subdomain': '', 'private': False}
    except ValueError:
        pass
    result = EXTRACT(hostname)
    return {'domain': result.top_domain_under_public_suffix or None,
            'subdomain': result.subdomain, 'private': result.is_private}


def misleading_subdomain(hostname, trusted):
    """Find a trusted hostname or its brand label in an unrelated subdomain.

    This is a name-placement indicator, not evidence of intent or ownership.
    Trust covers the exact expected host and its descendants, never suffix
    strings like apple.com.evil.com or notapple.com.
    """
    hostname, trusted = hostname.lower().rstrip('.'), trusted.lower().rstrip('.')
    if hostname == trusted or hostname.endswith('.' + trusted):
        return None
    submitted = domain_parts(hostname)
    expected = domain_parts(trusted)
    if not submitted['domain'] or not expected['domain']:
        return None
    if submitted['domain'] == expected['domain']:
        return None
    prefix = submitted['subdomain'].split('.') if submitted['subdomain'] else []
    trusted_labels = trusted.split('.')
    full_name = any(prefix[i:i+len(trusted_labels)] == trusted_labels
                    for i in range(len(prefix)))
    # Compare a complete subdomain label, not a substring such as pineapple.
    brand = EXTRACT(trusted).domain
    brand_name = len(brand) >= 3 and brand in prefix
    if full_name or brand_name:
        return submitted['domain']
    return None
