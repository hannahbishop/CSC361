import argparse
import sys
import dpkt
from connection import _Connection
import socket
import functools

def init_args():
    parser = argparse.ArgumentParser(description='Analyze a TCP capture file.')
    parser.add_argument('fs', type=str, help='a capture file to analyze')
    return parser.parse_args()

def add_connections(fp):
    connections = []
    rtt = {}
    pcap = dpkt.pcap.Reader(fp)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        src_ip = socket.inet_ntoa(ip.src)
        dest_ip = socket.inet_ntoa(ip.dst)
        conn = _Connection(src_ip, tcp.sport, dest_ip, tcp.dport)
        try:
            i = connections.index(conn)
        except ValueError:
            connections.append(conn)
        i = connections.index(conn)
        if tcp.flags & 4 == 4:
            connections[i].set_rst()
        if tcp.flags & 2 == 2:
            connections[i].inc_syn(ts)
        if tcp.flags & 1 == 1:
            connections[i].inc_fin(ts)
        connections[i].send_packet(src_ip, dest_ip, len(tcp.data), tcp.win)
        rtt[tcp.seq + len(tcp.data)] = ts
        if tcp.ack in rtt: 
            connections[i].add_rtt(ts - rtt[tcp.ack])
    return connections

def analyze_connections(connections):
    num_connections = 0
    complete = 0
    incomplete = 0
    reset = 0
    min_duration = min_packets = min_win = 99999999999
    max_duration = max_packets = max_win = 0
    total_duration = total_packets = total_win = 0

    durations = []
    rtt = []
    packets = []
    win = []

    for i, conn in enumerate(connections):
        num_connections += 1
        print("Connection {}\n".format(i + 1))
        conn.print_data()
        if conn.is_complete():
            complete += 1
            durations.append(conn.get_duration())
            packets.append(conn.get_num_packets())
            win += conn.get_win()
            rtt += conn.get_rtt()
        else:
            incomplete += 1
        if conn.get_rst():
            reset += 1
        print("\n------------------------------\n")
    print("Number of TCP Connections: {}".format(num_connections))
    print("Number of reset TCP connections observed in the trace: {}".format(reset))
    print("Number of TCP connections that were still open when the trace capture ended: {}".format(incomplete))
    print("Number of complete TCP connections observed in the trace: {}".format(complete))
    print("\n------------------------------\n")
    print("Complete Connections:\n")
    print("Minimum Time Duration: %.5f" % min(durations))
    print("Mean Time Duration: %.5f" % (sum(durations)/complete))
    print("Maximum Time Duration: %.5f\n" % max(durations))

    print("Minimum Packets (both directions): ", min(packets))
    print("Mean Packets (both directions): ", sum(packets)/complete)
    print("Maximum Packets (both directions): ", max(packets), "\n")
    
    print("Minimum receive window size (both directions): ", min(win))
    print("Mean receive window size (both directions): %.4f" % (sum(win)/complete))
    print("Maximum receive window size (both directions): ", max(win), "\n")

    print("Minimum RTT value: ", min(rtt))
    print("Mean RTT value: ", sum(rtt)/len(rtt))
    print("Maximum RTT value: ", max(rtt))
    
    return

def main():
    #fs = init_args().fs
    fp = open("sample-capture-file", "rb")
    connections = add_connections(fp)
    analyze_connections(connections)
    fp.close()
    return

if __name__ == "__main__":
    main()