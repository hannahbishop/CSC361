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

def durations(connections):
    durations = []
    for conn in connections:
        durations.append(conn.get_duration())
    return min(durations), (sum(durations)/len(connections)), max(durations)

def wins(connections):
    wins = []
    for conn in connections:
        wins += conn.get_win()
    return min(wins), (sum(wins)/len(connections)), max(wins)

def rtts(connections):
    rtts = []
    for conn in connections:
        rtts += conn.get_rtt()
    return min(rtts), (sum(rtts)/len(rtts)), max(rtts)

def packets(connections):
    packets = []
    for conn in connections:
        packets.append(conn.get_num_packets())
    return min(packets), (sum(packets)/len(connections)), max(packets)

def analyze_connections(connections):
    num_connections = 0
    num_complete = 0
    reset = 0
    complete = []

    for i, conn in enumerate(connections):
        num_connections += 1
        print("Connection {}\n".format(i + 1))
        conn.print_data()
        if conn.is_complete():
            complete.append(conn)
            num_complete += 1
        if conn.get_rst():
            reset += 1
    min_duration, mean_duration, max_duration = durations(complete)
    min_win, mean_win, max_win = wins(complete)
    min_rtt, mean_rtt, max_rtt = rtts(complete)
    min_packet, mean_packet, max_packet = packets(complete)
    print("Number of TCP Connections: {}".format(num_connections))
    print("Number of reset TCP connections observed in the trace: {}".format(reset))
    print("Number of TCP connections that were still open when the trace capture ended: {}".format(num_connections - num_complete))
    print("Number of complete TCP connections observed in the trace: {}".format(num_complete))
    print("\n------------------------------\n")
    print("Complete Connections:\n")
    print("Minimum Time Duration: %.5f" % min_duration)
    print("Mean Time Duration: %.5f" % mean_duration)
    print("Maximum Time Duration: %.5f\n" % max_duration)

    print("Minimum Packets (both directions): ", min_packet)
    print("Mean Packets (both directions): ", mean_packet)
    print("Maximum Packets (both directions): ", max_packet, "\n")
    
    print("Minimum receive window size (both directions): ", min_win)
    print("Mean receive window size (both directions): %.4f" % mean_win)
    print("Maximum receive window size (both directions): ", max_win, "\n")

    print("Minimum RTT value: ", min_rtt)
    print("Mean RTT value: ", mean_rtt)
    print("Maximum RTT value: ", max_rtt)
    
    return

def main():
    fs = init_args().fs
    fp = open(fs, "rb")
    connections = add_connections(fp)
    analyze_connections(connections)
    fp.close()
    return

if __name__ == "__main__":
    main()