import argparse
import socket, ssl, pprint
import re

#set up args
parser = argparse.ArgumentParser(description='Query a server.')
parser.add_argument('host', type=str, help='a URL to query')
args = parser.parse_args()

#create SSL socket
def createSSL():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    conn = context.wrap_socket(sock, server_hostname=args.host)
    return conn

#create regular socket
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

def receive(conn, print):
    recv = conn.recv(1024)
    resp = []
    while(recv):
        resp += recv.split(b"\r\n")
        recv = conn.recv(1024)
    if(print): pprint.pprint(resp)
    return resp

def supportHTTPS(host):
    try:
        conn = connectHTTPS(host)
        support = 1
    except:
        conn = connectHTTP(host)
        support = 0
    #finally:
        #To-Do: Add actual check?? Idk dude
    return support

def versionHTML(supportHTTPS, hostname):
    if supportHTTPS:
        conn = connectHTTPS(hostname)
    else:
        conn = connectHTTP(hostname)
    conn.sendall(b"HEAD / HTTP/1.0\r\nHost: " + hostname.encode() + b"\r\n\r\n")
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
        "Support HTTP: " + ("yes" if https else "no") + "\n"
        "Newest supported HTTP version: " + str(html) + "\n"
        "List of Cookies: " + cookies
    )
    
def main():
    #To-Do: Should I be using gethostbyname()?
    https = supportHTTPS("www.uvic.ca")
    html = versionHTML(https, "www.uvic.ca") or "// To-Do //"
    cookies = listCookies() or "// To-Do //"
    printServerInfo(https, html, cookies)

main()