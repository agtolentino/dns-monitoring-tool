# dns-monitoring-tool

A tool that scans a list of domain for DNS resolution and HTTP status code, response time, and SSL cert expiry. This includes a pipeline that runs tests on every push.

# Domain Health Monitor

[![CI](https://github.com/agtolentino/dns-monitoring-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/agtolentino/dns-monitoring-tool/actions/workflows/ci.yml)

A small Python command-line tool that checks a list of domains and reports which ones have problems. For each domain it checks **DNS**, **HTTP** and the **SSL certificate**, and flags the kinds of misconfiguration that make a site look "down" even though its DNS lookup succeeds.

## What it checks

| Check          | What it does                                                                   | Flags                                                                                                                |
| -------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| **DNS**        | Resolves the domain to an IP address                                           | Domain doesn't resolve                                                                                               |
| **Private IP** | Inspects the resolved IP                                                       | Public domain pointing at a private (RFC 1918) address such as `192.168.x.x`, which is unreachable from the internet |
| **HTTP**       | Requests `https://<domain>` with a 5 second timeout and measures response time | Timeouts, connection errors, and any 4xx/5xx response                                                                |
| **SSL**        | Reads the certificate and counts the days until it expires                     | Expired or invalid certificates, and certificates expiring within 14 days                                            |

If DNS fails or the IP is private, the HTTP and SSL checks are skipped. There is no point waiting on timeouts for a domain that can't be reached.

## Usage

```bash
pip install -r requirements.txt
python monitor.py              # reads domains.txt
python monitor.py my-list.txt  # or pass your own file
```

`domains.txt` takes one domain per line. Blank lines and lines starting with `#` are ignored:

```
# healthy sites
google.com
github.com

# deliberate failures, handy for demos
expired.badssl.com
this-domain-should-not-exist-12345.com
```

### Example output

```
DOMAIN                      STATUS   DETAILS
------------------------------------------------------------------------------
google.com                  OK       ip=142.250.4.138  http=200 (0.21s)  ssl=63d
github.com                  OK       ip=140.82.112.3  http=200 (0.34s)  ssl=118d
expired.badssl.com          PROBLEM  HTTP FAILED (...); SSL FAILED (certificate has expired)
this-domain-should-not-...  PROBLEM  DNS FAILED ([Errno -2] Name or service not known)
------------------------------------------------------------------------------
4 checked, 2 with problems
```

The exit code is `0` when everything is healthy and `1` when any domain has a problem, so the tool can be dropped into cron or a CI job and fail loudly.

## Project layout

```
checks.py          the individual checks: dns_check, is_private, http_check, ssl_check
monitor.py         command-line entry point: runs the checks and prints the report
test_checks.py     unit tests for the checks
domains.txt        the domains to monitor
requirements.txt   dependencies
.github/workflows/ci.yml   GitHub Actions pipeline
```

## Design notes

- **Checks never print and never crash on network errors.** Each returns a dict with `success`, a `result` and an `error`, so the caller decides what to do with it. A failed lookup is a normal result, not an exception.
- **Narrow exception handling.** Each check catches the specific errors it expects (for example `socket.gaierror` for DNS, `requests.Timeout` for HTTP) instead of a bare `except`, so unrelated bugs aren't hidden.
- **Tests never touch the real network.** Sockets, TLS, DNS and HTTP calls are faked, so the tests run in well under a second and give the same result on a laptop and in CI.

## Tests and CI

```bash
python -m pytest -v
```

Every push and pull request runs lint and the test suite on Python 3.10 and 3.12 through GitHub Actions (see the badge above).

## Possible next steps

- JSON output for feeding other tools
- Checking domains concurrently to speed up large lists
- Sending an alert (email or chat message) when a domain starts failing
