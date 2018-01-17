import argparse
import socket, ssl, pprint

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

def connectHTTPS():
    conn = createSSL()
    conn.connect((args.host, 443))
    return conn

def connectHTTP():
    sock = createSock()
    sock.connect((args.host, 80))
    return sock

def receive(conn):
    response = conn.recv(1024)
    while(response):
        pprint.pprint(response.split(b"\r\n"))
        response = conn.recv(1024)

def main():
    try:
        conn = connectHTTPS()
        print("SSL Connected")
        conn.sendall(b"HEAD / HTTP/1.0\r\nHost: " + args.host.encode() + b"\r\n\r\n")
        print("SSL Message Sent")
        receive(conn)
        print("SSL Message Received")
        conn.close()

    except:
        sock = connectHTTP()
        print("Non-SSL Connected")
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + args.host.encode() + b"\r\n\r\n")
        print("Non-SSL Message Sent")
        receive(conn)
        print("Non-SSL Message Received")
        sock.close()

main()
