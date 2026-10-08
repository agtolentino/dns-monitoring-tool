import ipaddress
import socket
import ssl
import time

import requests


#  DNS Check
def dns_check(domain):
    try:
        address = socket.gethostbyname(domain)
        return {"success": True, "result": address, "error": None}
    except socket.gaierror as ge:
        return {"success": False, "result": None, "error": str(ge)}


def is_private(address):
    try:
        ip_obj = ipaddress.ip_address(address)
        return {"is_private": ip_obj.is_private, "error": None}
    except ValueError as er:
        return {"is_private": None, "error": str(er)}


# HTTP
def http_check(domain):
    call_start = time.time()  # set before the try so every except block can use it
    try:
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain

        http_response = requests.get(domain, timeout=5)
        http_response.raise_for_status()  # makes 4xx/5xx raise HTTPError
        elapsed = time.time() - call_start
        return {"success": True, "result": http_response.status_code,
                "time elapsed": elapsed, "error": None}

    except requests.exceptions.HTTPError as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": error.response.status_code,
                "time elapsed": elapsed, "error": str(error)}

    except requests.exceptions.Timeout as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": None,
                "time elapsed": elapsed, "error": str(error)}

    except requests.exceptions.ConnectionError as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": None,
                "time elapsed": elapsed, "error": str(error)}

    except requests.RequestException as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": None,
                "time elapsed": elapsed, "error": str(error)}


# SSL
def ssl_check(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        expiry = ssl.cert_time_to_seconds(cert["notAfter"])
        days_left = int((expiry - time.time()) // 86400)
        return {"success": True, "result": days_left, "error": None}

    except ssl.SSLCertVerificationError as error:
        return {"success": False, "result": None, "error": str(error)}

    except socket.gaierror as error:
        return {"success": False, "result": None, "error": str(error)}

    except socket.timeout as error:
        return {"success": False, "result": None, "error": str(error)}

    except OSError as error:
        return {"success": False, "result": None, "error": str(error)}