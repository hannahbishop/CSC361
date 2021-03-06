import argparse
import socket
import ssl
import re
from urllib.parse import urlparse

#global constants
SUCCESS = [200, 404, 505, 503]
REDIRECT = [301, 302]
VERSION_SUCCESS = [200, 404]

def connect_to_host(host, https):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        print("Error resolving host.")
        raise Exception
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
    if status in SUCCESS:
        print("Support HTTPS: yes")
        return 1
    elif status in REDIRECT:
        o = urlparse(re.search(r"Location: (.*)", resp).group(1))
        if o.scheme == 'http':
            print("Support HTTPS: no")
            return o
        if o.scheme == 'https':
            return o
        return
    else:
        print("Unexpected status code in support_https(): ({status}). Exiting...".format(status=status))
        exit()

def send_request(host, request, https):
    try:
        conn = connect_to_host(host, https)
    except:
        print("Error connecting to host.")
        exit()
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
    print("\n\n" + resp + "\n")
    return resp

def find_cookies(https, host, path="/"):
    resp = send_request(host, ("HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").encode(), https)
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

def version_http(https, host, path = "/"):
    resp = send_request(host, ("HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").encode(), https)
    status = int(re.search(r"^(HTTP/1.[0|1])\s(\d+)", resp).group(2))
    if status == 505:
        return "1.1"
    elif status in SUCCESS:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = ctx.wrap_socket(sock, server_hostname=host)
        conn.connect((host, 443))
        return "2.0" if conn.selected_alpn_protocol() == "h2" else "1.1"
    else:
        return "1.0"
    return

def main():
    host = init_args().host
    print("website: {host}".format(host=host))
    https_result = support_https(host)
    redirects = 0
    path = "/"
    while(redirects <= 3):
        if isinstance(https_result, int):
            break
        else:            
            protocol = https_result.scheme
            if protocol == 'http':
                https_result = 0
                break
            redirects += 1
            host = https_result.netloc
            path = "/" if (https_result.path == "/\r") else https_result.path
            print('Redirecting to {host}{path}'.format(host=host, path=path))
            https_result = support_https(host, path)
    print("Newest Supported HTTP Version: " + version_http(https_result, host, path))
    find_cookies(https_result, host, path)
    return

main()