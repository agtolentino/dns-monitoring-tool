"""Unit tests for checks.py: is_private, ssl_check, dns_check, http_check.

Run from the project root:   python -m pytest -v

No test touches the real network. Sockets, TLS, DNS and HTTP calls are replaced
with fakes (monkeypatch), so the suite is fast and gives the same result on a
laptop and on GitHub Actions.
"""
import socket
import ssl
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

import checks


# ======================================================================
# 1. is_private(): pure logic, no mocking needed
#    is_private returns a dict: {"is_private": True/False/None, "error": ...}
# ======================================================================

@pytest.mark.parametrize("ip", ["10.0.0.1", "10.255.255.255", "172.16.0.1",
                                "172.31.255.255", "192.168.0.1", "192.168.1.10"])
def test_is_private_true_for_rfc1918_ranges(ip):
    result = checks.is_private(ip)

    assert result["is_private"] is True
    assert result["error"] is None


@pytest.mark.parametrize("ip", ["172.15.255.255", "172.32.0.1", "11.0.0.1",
                                "192.167.255.255", "192.169.0.1", "8.8.8.8", "1.1.1.1"])
def test_is_private_false_for_public_and_boundary_neighbours(ip):
    result = checks.is_private(ip)

    assert result["is_private"] is False
    assert result["error"] is None


@pytest.mark.parametrize("bad_input", ["not-an-ip", "999.999.999.999", "", None])
def test_is_private_returns_error_dict_for_invalid_input(bad_input):
    # A bad address (including None from a failed DNS lookup) must not crash.
    result = checks.is_private(bad_input)

    assert result["is_private"] is None
    assert result["error"]


# ======================================================================
# 2. ssl_check(): mock the network, control the clock
# ======================================================================

FAKE_NOW = 1_800_000_000  # a fixed "current time" so day counts are predictable


def _cert_expiring_in(days):
    """Build a fake getpeercert() dict that expires `days` after FAKE_NOW."""
    expiry = FAKE_NOW + days * 86400
    return {"notAfter": time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(expiry))}


def _fake_tls(monkeypatch, cert):
    """Replace socket/ssl/time inside checks so ssl_check never hits the network."""
    sock = MagicMock()
    sock.__enter__.return_value = sock

    secure_sock = MagicMock()
    secure_sock.__enter__.return_value = secure_sock
    secure_sock.getpeercert.return_value = cert

    context = MagicMock()
    context.wrap_socket.return_value = secure_sock

    create_connection = MagicMock(return_value=sock)

    monkeypatch.setattr(checks.socket, "create_connection", create_connection)
    monkeypatch.setattr(checks.ssl, "create_default_context", lambda: context)
    # Only checks.time is replaced, so pytest's own clock is untouched.
    monkeypatch.setattr(checks, "time", SimpleNamespace(time=lambda: FAKE_NOW))

    return SimpleNamespace(context=context, create_connection=create_connection)


def test_ssl_check_returns_days_left_on_success(monkeypatch):
    _fake_tls(monkeypatch, _cert_expiring_in(30))

    result = checks.ssl_check("example.com")

    assert result == {"success": True, "result": 30, "error": None}


def test_ssl_check_rounds_partial_days_down(monkeypatch):
    _fake_tls(monkeypatch, _cert_expiring_in(10.5))

    result = checks.ssl_check("example.com")

    assert result["result"] == 10


def test_ssl_check_reports_negative_days_for_past_expiry(monkeypatch):
    # Only reachable if verification lets an expired cert through, but the
    # arithmetic should still behave sensibly.
    _fake_tls(monkeypatch, _cert_expiring_in(-5))

    result = checks.ssl_check("example.com")

    assert result["success"] is True
    assert result["result"] < 0


def test_ssl_check_connects_to_port_443_with_a_timeout(monkeypatch):
    fakes = _fake_tls(monkeypatch, _cert_expiring_in(30))

    checks.ssl_check("example.com")

    args, kwargs = fakes.create_connection.call_args
    assert args[0] == ("example.com", 443)
    assert kwargs.get("timeout") is not None  # a hung domain must not hang the monitor


def test_ssl_check_sends_server_hostname_for_sni_and_name_checking(monkeypatch):
    fakes = _fake_tls(monkeypatch, _cert_expiring_in(30))

    checks.ssl_check("example.com")

    kwargs = fakes.context.wrap_socket.call_args.kwargs
    assert kwargs["server_hostname"] == "example.com"


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(socket.gaierror(-2, "Name or service not known"), id="dns-failure"),
        pytest.param(socket.timeout("timed out"), id="timeout"),
        pytest.param(ConnectionRefusedError("connection refused"), id="refused"),
        pytest.param(OSError("network is unreachable"), id="generic-oserror"),
    ],
)
def test_ssl_check_connection_errors_return_failure_dict(monkeypatch, error):
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(checks.socket, "create_connection", boom)

    result = checks.ssl_check("example.com")

    assert result["success"] is False
    assert result["result"] is None
    assert result["error"]  # some human-readable text, not empty


def test_ssl_check_certificate_verification_error_returns_failure_dict(monkeypatch):
    fakes = _fake_tls(monkeypatch, _cert_expiring_in(30))
    fakes.context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
        1, "certificate verify failed: certificate has expired"
    )

    result = checks.ssl_check("expired.example.com")

    assert result["success"] is False
    assert result["result"] is None
    assert "certificate" in result["error"]


# ======================================================================
# 3. dns_check(): resolves a name and returns the IP.
#    It does NOT judge the IP. is_private() does that, and monitor.py
#    combines the two (the SiteHost scenario).
# ======================================================================

def test_dns_check_succeeds_for_public_ip(monkeypatch):
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda domain: "93.184.216.34")

    result = checks.dns_check("example.com")

    assert result == {"success": True, "result": "93.184.216.34", "error": None}


def test_dns_result_feeds_is_private_for_the_sitehost_scenario(monkeypatch):
    # Public DNS answering with an unroutable address: dns_check returns the IP,
    # is_private flags it. This is the pair monitor.py uses.
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda domain: "192.168.1.10")

    dns = checks.dns_check("example.com")

    assert dns["success"] is True
    assert dns["result"] == "192.168.1.10"
    assert checks.is_private(dns["result"])["is_private"] is True


def test_dns_check_failure_when_domain_does_not_resolve(monkeypatch):
    def boom(domain):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(checks.socket, "gethostbyname", boom)

    result = checks.dns_check("no-such-domain.invalid")

    assert result["success"] is False
    assert result["result"] is None
    assert result["error"]


# ======================================================================
# 4. http_check(): fake requests.get with real Response objects
# ======================================================================

def _response(status_code=200, reason="OK"):
    """A real requests.Response, so raise_for_status() behaves like production."""
    response = requests.Response()
    response.status_code = status_code
    response.reason = reason
    response.url = "https://example.com"
    return response


def test_http_check_succeeds_on_200(monkeypatch):
    monkeypatch.setattr(checks.requests, "get", lambda *args, **kwargs: _response(200))

    result = checks.http_check("example.com")

    assert result["success"] is True
    assert result["result"] == 200
    assert result["error"] is None
    assert result["time elapsed"] >= 0


@pytest.mark.parametrize("status, reason", [
    (404, "Not Found"),
    (403, "Forbidden"),
    (500, "Internal Server Error"),
    (503, "Service Unavailable"),
])
def test_http_check_treats_4xx_and_5xx_as_failures(monkeypatch, status, reason):
    monkeypatch.setattr(
        checks.requests, "get", lambda *args, **kwargs: _response(status, reason)
    )

    result = checks.http_check("example.com")

    assert result["success"] is False
    assert result["result"] == status  # the status code is kept for the report
    assert str(status) in result["error"]


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(requests.Timeout("timed out"), id="timeout"),
        pytest.param(requests.ConnectionError("connection refused"), id="connection-error"),
        pytest.param(requests.RequestException("something else"), id="other-request-error"),
    ],
)
def test_http_check_network_errors_return_failure(monkeypatch, error):
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(checks.requests, "get", boom)

    result = checks.http_check("example.com")

    assert result["success"] is False
    assert result["result"] is None
    assert result["error"]
    assert result["time elapsed"] >= 0


def test_http_check_adds_https_and_a_timeout(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["timeout"] = kwargs.get("timeout")
        return _response(200)

    monkeypatch.setattr(checks.requests, "get", fake_get)

    checks.http_check("example.com")

    assert seen["url"] == "https://example.com"
    assert seen["timeout"] is not None  # a hung site must not hang the monitor


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com"])
def test_http_check_keeps_an_existing_scheme(monkeypatch, url):
    seen = {}

    def fake_get(called_url, **kwargs):
        seen["url"] = called_url
        return _response(200)

    monkeypatch.setattr(checks.requests, "get", fake_get)

    checks.http_check(url)

    assert seen["url"] == url