import dpkt
import datetime
import socket
from dpkt.compat import compat_ord
import sys
from UDP import _UDP
from ICMP import _ICMP
from RespLinux import _RespLinux
from RespWin import _RespWin

def extract_datagrams(pcap) -> (list, list, set):
    (incoming, outgoing) = ([], [])
    protocols = set()
    (linux, win) = (False, False)
    for ts, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        ip_src = socket.inet_ntoa(ip.src)
        ip_dst = socket.inet_ntoa(ip.dst)
        #UDP
        if ip.p == 17 and ip.ttl == len(outgoing) + 1:
            linux = True
            udp = _UDP(ip_src, ip_dst, ts, ip.ttl, ip.p, ip.data.sport, ip.data.dport)
            outgoing.append(udp)
        #ICMP
        if ip.p == 1:
            icmp_type = ip.data.type
            if icmp_type in (0, 8) and ip.ttl == len(outgoing) + 1:
                win = True
                seq = ip.data.data.seq
                icmp = _ICMP(ip_src, ip_dst, ts, ip.ttl, ip.p, seq)
                outgoing.append(icmp)
            if icmp_type == 11 and win:
                seq = ip.data.data.data.data['echo'].seq
                resp = _RespWin(ip_src, ip_dst, ts, ip.ttl, ip.p, seq)
                incoming.append(resp)
            if icmp_type == 11 and linux:
                port = ip.data.data.data.data.dport
                resp = _RespLinux(ip_src, ip_dst, ts, ip.ttl, ip.p, port)
                incoming.append(resp)
        protocols.add(ip.p)
            
    return (incoming, outgoing, protocols)

def find_path(incoming: list, outgoing: list) -> list:
    path = []
    #add the first
    path.append(outgoing[0].src)
    #add the intermediates
    for i, out in enumerate(outgoing):
        #UDP - match ports
        if out.p == 17:
            print(incoming[0].port)
        #ICMP - match seq number
        if out.p == 1:
            resp = [resp for resp in incoming if resp.seq == out.seq]
            if resp:
                path.append(resp[0].src)
    #add the last
    path.append(outgoing[0].dst)
    return path
        
def print_info(path):
    print("Source Node: ", path[0])
    print("Ultimate Destination Node: ", path[-1])
    print("Intermediate Nodes:")
    for i, ip in enumerate(path[1:-1]):
        print("  ", ip)

def main():
    with open("trace1.pcap", "rb") as fp:
        pcap = dpkt.pcap.Reader(fp)
        (incoming, outgoing, protocols) = extract_datagrams(pcap)
        path = find_path(incoming, outgoing)
        print_info(path)

if __name__ == "__main__":
    main()