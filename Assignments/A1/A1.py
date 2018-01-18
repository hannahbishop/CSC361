import argparse
import socket
import ssl
import pprint

#set up args
parser = argparse.ArgumentParser(description='Query a server.')
parser.add_argument('host', type=str, help='a URL to query')
args = parser.parse_args()

#global constants
HTTPS_SUCCESS = [200, 404, 505]
VERSION_SUCCESS = [200, 404]

def createSSL():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    conn = context.wrap_socket(sock, server_hostname=args.host)
    return conn

def createSock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock

def connectHTTPS(host):
    conn = createSSL()
    conn.connect((host, 443))
    return conn

def connectHTTP(host):
    sock = createSock()
    sock.connect((host, 80))
    return sock

def receive(conn):
    recv = conn.recv(1024)
    resp = []
    '''
    while(recv):
        #resp += recv
        pprint.pprint(recv)
        recv = conn.recv(1024)
        print("Hi")
    '''   
    resp += recv.split(b"\r\n")
    return resp

#Returns:
#   0 if Does Not Support
#   1 if Does Support
#   New location if redirect code
def supportHTTPS(host):
    try:
        conn = sendRequest (
            1, 
            "HEAD", 
            "1.1", 
            args.host
        )
        resp = receive(conn)
    except:
        return 0
    status = getStatusCode(resp[0])
    if status in HTTPS_SUCCESS: return 1
    elif status == 302:
        #Get redirect location
        return "Location"
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
    return conn
    
def versionHTML(supportHTTPS, hostname):
    https = 1 if supportHTTPS else 0
    sendRequest(
        https, 
        "HEAD", 
        "1.1", 
        args.host
    )
    response = receive(conn, print)
    #conn.close()
    #To-Do: Use regex to search HTML header for HTTP version
    return

def listCookies():
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
def getStatusCode(status):
    digits = [int(s) for s in status.split() if s.isdigit()]
    return digits[0]

def main():

    https = supportHTTPS(args.host)
    if isinstance(https, str):
        print("Redirected. Querying new address...")
        https = supportHTTPS(args.host)
    elif https:
        print("Now proceed with other things using HTTPS")
        #proceed with other things using https
    else:
        print("Now proceed with other things using HTTP")
        #proceed with other things using http
    printServerInfo(https, -1, "")
    '''
    html = versionHTML(https, args.host) or "// To-Do //"
    cookies = listCookies() or "// To-Do //"
    printServerInfo(https, html, cookies)
    '''

main()