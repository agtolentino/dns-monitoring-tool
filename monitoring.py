import socket
import ipaddress
import time
import requests


def dns_check(domain):
    try:
        address = socket.gethostbyname(domain)
        return {"success": True, "result": address, "error": None}
    except socket.gaierror as ge:
        return {"success": False, "result": None, "error": str(ge)}

def is_private(address):
    try:
        # print(address)
        address = ipaddress.ip_address(address)
        address_type = address.is_private
        return {"is_private":address_type, "error": None}
    except ValueError as er:
        return {"is_private": None, "error": str(er)}


def http_check(domain):
    try:
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain
        call_start = time.time()
        http_response = requests.get(domain, timeout=5)
        elapsed = time.time() - call_start
        return {"success": True, "result": http_response,"time elapsed" : elapsed, "error": None}
    
    except requests.exceptions.ConnectionError as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": error.response,"time elapsed" : elapsed, "error": None}
    
    except requests.exceptions.HTTPError as error:
            elapsed = time.time() - call_start
            return {"success": False, "result": error.response,"time elapsed" : elapsed, "error": None}

    except requests.exceptions.Timeout as error:
                elapsed = time.time() - call_start
                return {"success": False, "result": error.response,"time elapsed" : elapsed, "error": None}
    
    except requests.RequestException as error:
        elapsed = time.time() - call_start
        return {"success": False, "result": error.response,"time elapsed" : elapsed, "error": None}





# test1 = dns_check("google.com")
# print(test1)
# test2 = is_private(test1['result'])
# print(test2)

# test3 = dns_check("kaggging.com")
# test4 = is_private(test3['result'])
# print(test3)
# print(test4)


# start = time.time()
# response = requests.get("https://google.com", timeout=5)
# elapse = time.time() - start

# print(response.status_code)

# data = http_check("kaminggoogle.com")
# print(data)
data = http_check("kaggle.com")
print(data)
