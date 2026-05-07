"""Test that RRFResolverFromEnv sends a non-default User-Agent.

Regression test for: Cloudflare in front of robotregistryfoundation.org
rejects the default Python-urllib UA with HTTP 403, silently swallowed by
the resolver's broad-except, surfacing as bogus 'kid not registered'
denies in the gateway. The fix is to send a proper UA.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from robot_md_gateway.auth import RRFResolverFromEnv


def test_resolver_sends_user_agent_header():
    """Verify the resolver adds a User-Agent header on outbound HTTP."""
    resolver = RRFResolverFromEnv("https://example.test")

    captured_request = {}

    class _FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self):
            return b'{"public_key_pem": "-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----\\n"}'

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured_request["url"] = req.full_url
        captured_request["headers"] = dict(req.headers)
        return _FakeResponse()

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        result = resolver.resolve_public_key_pem("test-kid")

    assert result is not None
    assert result.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert captured_request["url"] == "https://example.test/v2/keys/test-kid"
    # urllib normalizes header keys to title-case
    assert "User-agent" in captured_request["headers"]
    ua = captured_request["headers"]["User-agent"]
    assert "robot-md-gateway" in ua
    assert "kid-resolver" in ua


def test_resolver_caches_pem_after_first_fetch():
    """Cache hit on subsequent calls — should not invoke urlopen twice."""
    resolver = RRFResolverFromEnv("https://example.test")
    call_count = {"n": 0}

    class _FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self):
            return b'{"public_key_pem": "-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----\\n"}'

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        call_count["n"] += 1
        return _FakeResponse()

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        a = resolver.resolve_public_key_pem("k")
        b = resolver.resolve_public_key_pem("k")

    assert a == b
    assert call_count["n"] == 1


def test_resolver_returns_none_on_403():
    """A 403 (e.g., CF WAF rejection) returns None, not a partial PEM."""
    resolver = RRFResolverFromEnv("https://example.test")

    class _FakeError(Exception):
        pass

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        result = resolver.resolve_public_key_pem("blocked-kid")

    assert result is None
