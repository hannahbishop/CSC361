import argparse
import sys
import dpkt
from connection import _Connection
import socket

def init_args():
    parser = argparse.ArgumentParser(description='Analyze a TCP capture file.')
    parser.add_argument('fs', type=str, help='a capture file to analyze')
    return parser.parse_args()

def add_connections(fp):
    connections = []
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
    return connections

def analyze_connections(connections):
    num_connections = 0
    complete = 0
    incomplete = 0
    reset = 0
    max_duration = 0
    min_duration = 99999999999
    total_duration = 0
    max_packets = 0
    min_packets = 99999999999
    total_packets = 0
    max_win = 0
    min_win = 99999999999
    total_win = 0
    for i, conn in enumerate(connections):
        num_connections += 1
        print("Connection {}\n".format(i + 1))
        conn.print_data()
        if conn.is_complete():
            complete += 1
            duration = conn.get_duration()
            packets = conn.get_num_packets()
            win = conn.get_win()
            total_packets += packets
            total_duration += duration
            if duration > max_duration:
                max_duration = duration
            if duration < min_duration:
                min_duration = duration
            if packets > max_packets:
                max_packets = packets
            if packets < min_packets:
                min_packets = packets
            for win in win:
                total_win += win
                if win > max_win:
                    max_win = win
                if win < min_win:
                    min_win = win
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
    print("Minimum Time Duration: %.5f" % min_duration)
    print("Mean Time Duration: %.5f" % (total_duration/complete))
    print("Maximum Time Duration: %.5f\n" % max_duration)

    print("Minimum Packets (both directions): ", min_packets)
    print("Mean Packets (both directions): %.4f" % (total_packets/complete))
    print("Maximum Packets (both directions): ", max_packets, "\n")
    
    print("Minimum receive window size (both directions): ", min_win)
    print("Mean receive window size (both directions): %.4f" % (total_win/complete))
    print("Maximum receive window size (both directions): ", max_win)
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