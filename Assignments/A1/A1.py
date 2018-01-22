import argparse
import socket
import ssl
import re
from urllib.parse import urlparse

#global constants
HTTPS_SUCCESS = [200, 404, 505]
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
def supportHTTPS(host):
    try:
        resp = sendRequest (
            1, 
            "HEAD", 
            "1.1", 
            host
        )
    except:
        print("supportHTTPS() exception")
        return 0
    status = getStatusCode(resp)
    if status in HTTPS_SUCCESS: 
        print("HTTP Status Code: " + str(status))
        print("Supports HTTPS: yes")
        return 1
    elif status == 302:
        o = urlparse(re.search(r"Location: (.*)", resp).group(1))
        return o.netloc
    else:
        print("HTTPS Support Testing Error. Exiting...")
        exit()

#Sends an HTTP(S) request, and returns the response as a byte list.
#Version must be in [1.0, 1.1, 2]
def sendRequest(https, method, version, host):
    if (https):
        conn = connectHTTPS(host)
    else:
        conn = connectHTTP(host)
    conn.sendall(
        method.encode() +
        b" / HTTP/" +
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
    #conn.close()
    #To-Do: Use regex to search HTML header for HTTP version
    return

def findCookies(HTTPS, HTML, host):
    resp = sendRequest (
        HTTPS, 
        "HEAD", 
        HTML, 
        host
    )
    print("List of Cookies:")
    for (m) in re.findall(r"Set-Cookie: (.*?)=(.*?);.* (domain=(.*))?", resp):
        domain = host[3:] + " (default)" if (m[3] == '') else m[3]
        print('name: {name}\tkey: {key}\tdomain: {domain}'.format(name=m[0], key=m[1], domain=domain))
    #To-Do: Use regex to search the server response for cookies
    return

def printServerInfo(https, html, cookies):
    print(
        "website: // To-Do //" + "\n"
        "Support HTTPS: " + ("yes" if https else "no") + "\n"
        "Newest supported HTTP version: " + str(html) + "\n"
        "List of Cookies: " + cookies
    )
    
#Status must be a string, to be parsed
def getStatusCode(response):
    status_code = int(re.search(r"^(HTTP/1.[0|1])\s(\d+)", response).group(2))
    return status_code

def initArgs():
    parser = argparse.ArgumentParser(description='Query a server.')
    parser.add_argument('host', type=str, help='a URL to query')
    return parser.parse_args()

def main():
    args = initArgs()
    host = args.host
    redirects = 0
    while(redirects < 2):
        httpsResult = supportHTTPS(host)
        if isinstance(httpsResult, int): break
        else: 
            redirects += 1
            if redirects >= 2:
                print("Too many redirects. Exiting...")
                exit()
            else:
                print('302 Status Code. Redirecting to {location}'.format(location=httpsResult))
                host = supportHTTPS(httpsResult)
    if httpsResult:
        print("Now proceed with other things using HTTPS")
        findCookies(1, "1.1", host)
        '''
        html = versionHTML(https, host) or "// To-Do //"
        '''
    else:
        print("Now proceed with other things using HTTP")
        findCookies(1, "1.1", host)
        '''
        html = versionHTML(https, host) or "// To-Do //"
        '''
    '''
    html = versionHTML(https, host) or "// To-Do //"
    cookies = findCookies() or "// To-Do //"
    printServerInfo(https, html, cookies)
    '''

main()

'''
initialize args
redirects = 0
while(redirects < 2):
    get supporthttps result
    if isinstance(httpsResult, int): break
    else: 
        redirects = redirects + 1
        if redirects >= 2:
            print("Too many redirects. Exiting...")
            exit()
        else:
            print('302 Status Code. Redirecting to {location}'.format(location=httpsResult))
            https = supportHTTPS(httpsResult)
'''