import sys

from monitoring_checks import dns_check, is_private, http_check, ssl_check

SSL_WARN_DAYS = 14


def load_domains(filename):
    domains = []
    with open(filename) as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # tolerate "https://example.com/" in the file
            line = line.replace("https://", "").replace("http://", "").rstrip("/")
            domains.append(line)
    return domains


def check_domain(domain):
    problems = []
    report = {"domain": domain, "ip": None, "status_code": None,
              "response_time": None, "ssl_days_left": None, "problems": problems}

    # DNS first: no point waiting on HTTP/SSL timeouts if the domain doesn't resolve
    dns = dns_check(domain)
    if not dns["success"]:
        problems.append(f"DNS FAILED ({dns['error']})")
        return report
    report["ip"] = dns["result"]

    # A public domain pointing at a private IP is unreachable from the internet
    private = is_private(dns["result"])
    if private["is_private"]:
        problems.append(f"PRIVATE IP ({dns['result']})")
        return report

    http = http_check(domain)
    report["status_code"] = http["result"]
    report["response_time"] = http["time elapsed"]
    if not http["success"]:
        problems.append(f"HTTP FAILED ({str(http['error'])[:80]})")

    ssl_result = ssl_check(domain)
    report["ssl_days_left"] = ssl_result["result"]
    if not ssl_result["success"]:
        problems.append(f"SSL FAILED ({str(ssl_result['error'])[:80]})")
    elif ssl_result["result"] < SSL_WARN_DAYS:
        problems.append(f"SSL EXPIRES SOON ({ssl_result['result']} days)")

    return report


def print_report(reports):
    print(f"{'DOMAIN':<28}{'STATUS':<9}DETAILS")
    print("-" * 78)
    for report in reports:
        if report["problems"]:
            print(f"{report['domain']:<28}{'PROBLEM':<9}{'; '.join(report['problems'])}")
        else:
            details = (f"ip={report['ip']}  http={report['status_code']} "
                       f"({report['response_time']:.2f}s)  ssl={report['ssl_days_left']}d")
            print(f"{report['domain']:<28}{'OK':<9}{details}")

    failing = 0
    for report in reports:
        if report["problems"]:
            failing += 1
    print("-" * 78)
    print(f"{len(reports)} checked, {failing} with problems")
    return failing


def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else "domains.txt" #update to match intented .txt file
    domains = load_domains(filename)

    reports = []
    for domain in domains:
        reports.append(check_domain(domain))

    failing = print_report(reports)
    if failing:
        sys.exit(1)  # non-zero exit lets CI / cron notice a problem


if __name__ == "__main__":
    main()