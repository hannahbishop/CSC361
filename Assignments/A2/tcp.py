import argparse
import sys
import dpkt
from connection import _Connection
import socket

def init_args():
    parser = argparse.ArgumentParser(description='Analyze a TCP capture file.')
    parser.add_argument('fs', type=str, help='a capture file to analyze')
    return parser.parse_args()

def packet_loop(fp):
    connections = []
    pcap = dpkt.pcap.Reader(fp)
    count = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        flags = format(tcp.flags, '08b')
        syn = int(flags[6])
        fin = int(flags[7])
        src_ip = socket.inet_ntoa(ip.src)
        dest_ip = socket.inet_ntoa(ip.dst)
        conn = _Connection(src_ip, tcp.sport, dest_ip, tcp.dport, [syn, fin])
        try:
            i = connections.index(conn)
            if tcp.flags & 2 == 2:
                connections[i].inc_syn(ts)
            if tcp.flags & 1 == 1:
                connections[i].inc_fin(ts)
        except ValueError:
            connections.append(conn)
    for conn in connections:
        if conn.is_complete():
            conn.print_data()
            print("--------")
    return


def main():
    #fs = init_args().fs
    fp = open("sample-capture-file", "rb")
    packet_loop(fp)
    fp.close()
    return

if __name__ == "__main__":
    main()