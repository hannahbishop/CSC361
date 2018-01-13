import argparse
import socket, ssl, pprint

#set up args
parser = argparse.ArgumentParser(description='Query a server.')
parser.add_argument('host', type=str, help='a URL to query')
args = parser.parse_args()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    conn = context.wrap_socket(sock, server_hostname="www.uvic.ca")
    try:
        conn.connect(("www.uvic.ca", 443))
        conn.sendall(b"HEAD / HTTP/1.1\r\nHost: www.uvic.ca\r\n\r\n")
        pprint.pprint(conn.recv(1024).split(b"\r\n"))
    finally:
        conn.close()

main()
