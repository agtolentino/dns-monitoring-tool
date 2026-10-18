"""Tests for checks.py (is_private, ssl_check, dns_check, http_check).

Run from the project root:   python -m pytest -v

This is a tentative Unit tests written to test IP check logic, mock SSL, and dns checks

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
# ======================================================================

@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",          # 10.0.0.0/8, low end
        "10.255.255.255",    # 10.0.0.0/8, high end
        "172.16.0.1",        # 172.16.0.0/12, low end
        "172.31.255.255",    # 172.16.0.0/12, high end
        "192.168.0.1",       # 192.168.0.0/16, low end
        "192.168.1.10",      # the address from the SiteHost challenge
    ],
)
def test_is_private_true_for_rfc1918_ranges(ip):
    assert checks.is_private(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "172.15.255.255",    # just BELOW 172.16.0.0/12
        "172.32.0.1",        # just ABOVE 172.16.0.0/12
        "11.0.0.1",          # just above 10.0.0.0/8
        "192.167.255.255",   # just below 192.168.0.0/16
        "192.169.0.1",       # just above 192.168.0.0/16
        "8.8.8.8",           # ordinary public IP
        "1.1.1.1",           # ordinary public IP
    ],
)
def test_is_private_false_for_public_and_boundary_neighbours(ip):
    assert not checks.is_private(ip)


def test_is_private_rejects_garbage_input():
    # ASSUMPTION: your function lets a bad address raise ValueError (what the
    # ipaddress module does). If yours returns False instead, change this test
    # to match, but decide on purpose which behaviour you want.
    with pytest.raises(ValueError):
        checks.is_private("not-an-ip")


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
# 3. dns_check() and http_check()  (ASSUMPTIONS: see module docstring)
#
# Assumed: dns_check resolves with socket.gethostbyname and http_check calls
# requests.get; both return a dict with at least "success" and "error", like
# ssl_check. Change the patch targets and keys to match your real code.
# ======================================================================

def test_dns_check_succeeds_for_public_ip(monkeypatch):
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda domain: "93.184.216.34")

    result = checks.dns_check("example.com")

    assert result["success"] is True
    assert "93.184.216.34" in str(result)


def test_dns_check_flags_private_ip(monkeypatch):
    # The SiteHost scenario: public DNS answering with an unroutable address.
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda domain: "192.168.1.10")

    result = checks.dns_check("example.com")

    assert "private" in str(result).lower()


def test_dns_check_failure_when_domain_does_not_resolve(monkeypatch):
    def boom(domain):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(checks.socket, "gethostbyname", boom)

    result = checks.dns_check("no-such-domain.invalid")

    assert result["success"] is False
    assert result["error"]


def _fake_response(status_code=200, http_error=None):
    response = MagicMock()
    response.status_code = status_code
    if http_error is not None:
        response.raise_for_status.side_effect = http_error
    return response


def test_http_check_succeeds_on_200(monkeypatch):
    monkeypatch.setattr(
        checks.requests, "get", lambda *args, **kwargs: _fake_response(200)
    )

    result = checks.http_check("example.com")

    assert result["success"] is True
    assert "200" in str(result)


def test_http_check_fails_on_server_error(monkeypatch):
    error = requests.HTTPError("500 Server Error: Internal Server Error")
    monkeypatch.setattr(
        checks.requests, "get", lambda *args, **kwargs: _fake_response(500, error)
    )

    result = checks.http_check("example.com")

    assert result["success"] is False
    assert result["error"]


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(requests.Timeout("timed out"), id="timeout"),
        pytest.param(requests.ConnectionError("connection refused"), id="connection-error"),
    ],
)
def test_http_check_network_errors_return_failure(monkeypatch, error):
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(checks.requests, "get", boom)

    result = checks.http_check("example.com")

    assert result["success"] is False
    assert result["error"]