import argparse
import socket
import ssl
import re
from urllib.parse import urlparse

#global constants
HTTPS_SUCCESS = [200, 404, 505, 503]
REDIRECT = [301, 302]
VERSION_SUCCESS = [200, 404]

def connect_to_host(host, https):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    if https:
        port = 443
        try:
            context = ssl.create_default_context()
            secure = context.wrap_socket(sock, server_hostname=host)
            secure.connect((host, port))
        except ssl.SSLError:
            raise Exception
        return secure
    else:
        port = 80
        sock.connect((host, port))
        return sock


#Returns:
#   0 if Does Not Support
#   1 if Does Support
#   New location if redirect code
def support_https(host, path = "/"):
        https_request = ("HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").encode()
    try:
        resp = send_request(host, https_request, 1)
    except:
        print("Support HTTPS: no")
        return 0
    status = int(re.search(r"^(HTTP/1.[0|1])\s(\d+)", resp).group(2))
    if status in HTTPS_SUCCESS:
        print("Support HTTPS: yes")
        return 1
    elif status in REDIRECT:
        o = urlparse(re.search(r"Location: (.*)", resp).group(1))
        if o.scheme == 'http':
            #redirect url is http, so https not supported
            print("Support HTTPS: no")
            return o
        if o.scheme == 'https':
            #needs further checking
            return o
        return
    else:
        print("Unexpected status code in support_https(): ({status}). Exiting...".format(status=status))
        sys.exit()

def send_request(host, request, https):
    conn = connect_to_host(host, https)
    conn.sendall(request)
    resp = b""
    try:
        while True:
            received = conn.recv(1024)
            if received:
                resp += received
            else:
                break
    except socket.timeout:
        pass
    resp = resp.decode("utf-8")
    return resp

def find_cookies(https, html, host):
    resp = send_request(host, ("HEAD / HTTP/1.1\r\nHost: " + host + "\r\n\r\n").encode(), https)
    print("List of Cookies:\n")
    for (m) in re.findall(r"Set-Cookie: (.*?)=(.*?);.* (domain=(.*))?", resp):
        d = re.search(r".*?(\..*)", host).group(1) #get default host
        domain = d + " (default)" if (m[3] == '') else m[3]
        print('\tname: {name}\n\tkey: {key}\n\tdomain: {domain}\n\n'.format(name=m[0], key=m[1], domain=domain))
    return

def init_args():
    parser = argparse.ArgumentParser(description='Query a server.')
    parser.add_argument('host', type=str, help='a URL to query')
    return parser.parse_args()

def main():
    host = init_args().host
    print("website: {host}".format(host=host))
    https_result = support_https(host)
    redirects = 0
    while(redirects < 3):
        if isinstance(https_result, tuple):
            redirects += 1
            host = https_result.netloc
            protocol = https_result.scheme
            path = "" if (https_result.path == "/\r") else https_result.path
            if protocol == 'http':
                https_result = 0
                break
            else:
                print('Redirecting to {host}{path}'.format(host=host, path=path))
                https_result = support_https(host, path)
        else:
            break
    if redirects >= 3:
        print("Too many redirects. Exiting...")
        sys.exit()
    if https_result:
        find_cookies(1, "1.1", host)
    else:
        find_cookies(0, "1.1", host)

main()