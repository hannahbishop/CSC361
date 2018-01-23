import argparse
import socket
import ssl
import re
from urllib.parse import urlparse

#global constants
HTTPS_SUCCESS = [200, 404, 505, 503]
REDIRECT = [301, 302]
VERSION_SUCCESS = [200, 404]

def createSSL(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    context = ssl.create_default_context()
    conn = context.wrap_socket(sock, server_hostname=host)
    return conn

def createSock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    return sock

def connectHTTPS(host):
    conn = createSSL(host)
    conn.connect((host, 443))
    return conn

def connectHTTP(host):
    sock = createSock()
    sock.connect((host, 80))
    return sock

#Returns:
#   0 if Does Not Support
#   1 if Does Support
#   New location if redirect code
def supportHTTPS(host, path = ""):
    try:
        resp = sendRequest (
            1, 
            "HEAD", 
            "1.1", 
            host,
            (path or "/"),
        )
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
        print("HTTPS Support Testing Error: Unexpected status code ({status}). Exiting...".format(status=status))
        exit()

#Sends an HTTP(S) request, and returns the response as a byte list.
#Version must be in [1.0, 1.1, 2]
def sendRequest(https, method, version, host, path = ""):
    if (https):
        conn = connectHTTPS(host)
    else:
        conn = connectHTTP(host)
    conn.sendall(
        method.encode() +
        b" " +
        (path or "/").encode() +
        b" HTTP/" +
        version.encode() +
        b"\r\nHost: " + 
        host.encode() + 
        b"\r\n\r\n"
    )
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
    
def versionHTML(supportHTTPS, host):
    https = 1 if supportHTTPS else 0
    resp = sendRequest(
        https, 
        "HEAD", 
        "1.1", 
        host
    )
    return

def findCookies(HTTPS, HTML, host):
    resp = sendRequest (
        HTTPS, 
        "HEAD", 
        HTML, 
        host
    )
    print("List of Cookies:\n")
    for (m) in re.findall(r"Set-Cookie: (.*?)=(.*?);.* (domain=(.*))?", resp):
        d = re.search(r".*?(\..*)", host).group(1) #get default host
        domain = d + " (default)" if (m[3] == '') else m[3]
        print('\tname: {name}\n\tkey: {key}\n\tdomain: {domain}\n\n'.format(name=m[0], key=m[1], domain=domain))
    return

def initArgs():
    parser = argparse.ArgumentParser(description='Query a server.')
    parser.add_argument('host', type=str, help='a URL to query')
    return parser.parse_args()

def main():
    args = initArgs()
    host = args.host
    print("website: {host}".format(host=host))
    redirects = 0
    httpsResult = supportHTTPS(host)
    while(redirects < 3):
        if isinstance(httpsResult, tuple):
            redirects += 1
            host = httpsResult.netloc
            protocol = httpsResult.scheme
            path = "" if (httpsResult.path == "/\r") else httpsResult.path
            if protocol == 'http':
                httpsResult = 0
                break
            else:
                print('Redirecting to {host}{path}'.format(host=host, path=path))
                httpsResult = supportHTTPS(host, path)
        else:
            break
    if redirects >= 3:
        print("Too many redirects. Exiting...")
        exit()
    if httpsResult:
        findCookies(1, "1.1", host)
    else:
        findCookies(0, "1.1", host)

main()