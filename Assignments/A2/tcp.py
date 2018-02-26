import argparse
import sys
import dpkt
from connection import _Connection

def init_args():
    parser = argparse.ArgumentParser(description='Analyze a TCP capture file.')
    parser.add_argument('fs', type=str, help='a capture file to analyze')
    return parser.parse_args()

def packet_loop(fp):
    connections = []
    pcap = dpkt.pcap.Reader(fp)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        conn = _Connection(ip.src, tcp.sport, ip.dst, tcp.dport, format(tcp.flags, '06b'))
        if conn in connections:
            continue
        else:
            connections.append(conn)
    return


def main():
    #fs = init_args().fs
    fp = open("trace.cap", mode="r+b")
    packet_loop(fp)
    fp.close()
    return

if __name__ == "__main__":
    main()