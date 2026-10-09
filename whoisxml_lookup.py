"""Server-side, hostname-only WhoisXML lookup. Never log request URLs."""
from __future__ import annotations

import json
import re
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler

from threat_intelligence import ThreatIntelligenceFinding

ENDPOINT = "https://threat-intelligence.whoisxmlapi.com/api/v1"
MAX_RESPONSE_BYTES = 512 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def unavailable(detail="Threat intelligence could not be checked. Please try again later."):
    return ThreatIntelligenceFinding(
        source="WhoisXML API", status="unavailable", classification="none",
        match_type="none", verified=False, detail=detail,
    )


def parse_response(payload, hostname):
    if not isinstance(payload, dict):
        raise ValueError("Invalid response")
    total, records = payload.get("total"), payload.get("results")
    if type(total) is not int or total < 0 or not isinstance(records, list):
        raise ValueError("Invalid response")
    if total == 0 and not records:
        return ThreatIntelligenceFinding(
            source="WhoisXML API", status="not_found", classification="none",
            match_type="none", verified=False,
            detail="No threat records matching this hostname were returned. This does not guarantee that the domain or link is safe.",
        )
    # Accept only an exact domain record. Unexpected or incomplete matches
    # must never become a clean result or a hostname listing.
    matches = [r for r in records if isinstance(r, dict)
               and r.get("iocType") == "domain"
               and isinstance(r.get("value"), str)
               and r["value"].lower().rstrip(".") == hostname]
    if total < len(records) or not matches:
        raise ValueError("Unexpected matches")
    return ThreatIntelligenceFinding(
        source="WhoisXML API", status="listed", classification="source_reported",
        match_type="hostname", verified=False,
        detail="WhoisXML API returned a threat-intelligence record for this hostname. This is a source-reported association, not an independent FDF determination of malicious activity. The full URL was not checked.",
    )


class WhoisXMLClient:
    def __init__(self, api_key, *, hourly_limit=10, cache_seconds=900, opener=None, clock=time.monotonic):
        self._api_key = api_key
        self._limit = hourly_limit
        self._ttl = cache_seconds
        self._opener = opener or build_opener(NoRedirects())
        self._clock = clock
        self._lock = threading.Lock()
        self._cache = {}
        self._calls = []

    def lookup(self, hostname):
        hostname = hostname.lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", hostname):
            return unavailable()
        if not self._api_key:
            return unavailable()
        # Serialize requests within this worker to avoid duplicate concurrent
        # calls for the same hostname and enforce its local rolling cap.
        with self._lock:
            now = self._clock()
            self._cache = {k: v for k, v in self._cache.items() if now - v[0] < self._ttl}
            if hostname in self._cache:
                return self._cache[hostname][1]
            self._calls = [t for t in self._calls if now - t < 3600]
            if len(self._calls) >= self._limit:
                return unavailable("The intelligence lookup usage limit has been reached. Domain-name analysis is still available.")
            self._calls.append(now)
            query = urlencode({"apiKey": self._api_key, "ioc": hostname, "size": 100, "outputFormat": "JSON"})
            try:
                req = Request(ENDPOINT + "?" + query, headers={"Accept": "application/json"})
                with self._opener.open(req, timeout=5) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("Oversized response")
                finding = parse_response(json.loads(raw), hostname)
            except Exception:
                # Provider exception strings may contain the credential-bearing
                # URL. Do not log or surface them, and never mark errors clean.
                return unavailable()
            self._cache[hostname] = (self._clock(), finding)
            return finding
