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

def main():
    try:
        conn = connectSSL()
        conn.connect((args.host, 443))
        conn.sendall(b"HEAD / HTTP/1.1\r\nHost: " + args.host + "\r\n\r\n")
        pprint.pprint(conn.recv(1024).split(b"\r\n"))
        conn.close()
    except:
        sock = createSock()
        sock.connect((args.host, 80))
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + args.host + "\r\n\r\n")
        pprint.pprint(sock.recv(1024).split(b"\r\n"))
        sock.close()

main()
