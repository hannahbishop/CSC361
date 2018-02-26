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
        flags = format(tcp.flags, '08b')
        conn = _Connection(ip.src, tcp.sport, ip.dst, tcp.dport, flags)
        #messy, fix this. can I just edit in place? this looks terrible
        if conn in connections:
            for i in range(len(connections)):
                if connections[i] == conn:
                    #increment syn and fin if they are set
                    if (tcp.flags & 0b00000010) == 2:
                        print("inc syn")
                        connections[i].inc_syn()
                    if (tcp.flags & 0b00000001) == 1:
                        print("inc fin")
                        connections[i].inc_fin()
        else:
            connections.append(conn)
    for conn in connections:
        conn.print()
    return


def main():
    #fs = init_args().fs
    fp = open("trace.cap", mode="r+b")
    packet_loop(fp)
    fp.close()
    return

if __name__ == "__main__":
    main()