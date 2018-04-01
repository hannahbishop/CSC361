import sys
import dpkt
import pcap
import ipaddress
import datetime
import socket
from dpkt.compat import compat_ord
from operator import itemgetter

# GLOBAL VARIABLES
int_dest = {}
protocols = []


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_icmp(pcap):
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Now check if this is an ICMP packet
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
            print( 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
            print( 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                  (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
            print('ICMP: type:%d code:%d checksum:%d data: %s\n' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))

def parse_proto(proto):
	proto_mappings = {1: 'ICMP',
					  6: 'TCP', 
					  17: 'UDP', 
					  47: 'GRE'}
	return proto_mappings[proto]


def get_icmp(pc):
	icmp_count = 0
	for ts, buf in pc:
		eth = dpkt.ethernet.Ethernet(buf)
		if not isinstance(eth.data, dpkt.ip.IP):
			continue

		ip = eth.data

		# if ICMP
		if isinstance(ip.data, dpkt.icmp.ICMP):
			icmp_count += 1
			icmp = ip.data
			this_source = inet_to_str(ip.src)

			# if this is first ICMP, print source and dest
			if (icmp_count == 1):
				source_ip = this_source
				ult_dest = inet_to_str(ip.dst)
				print ('The IP address of the source node: {}'.format(source_ip))
				print ('The IP address of the ultimate destination node: {}'.format(ult_dest))

			# store intermediate destinations and TTLs into int_dest
			if ((source_ip == this_source) | (this_source in int_dest)):
				continue
			else:
				int_dest[this_source] = ip.ttl

		# check protocol
		this_proto = parse_proto(ip.p)
		if not ([ip.p, this_proto] in protocols):
			protocols.append([ip.p, this_proto])


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print ('Error: Please specify a traceroute file.')
		exit()

	pc = pcap.pcap(sys.argv[1])
	print ('')

	get_icmp(pc)

	# create list in order of TTL of intermediate destinations
	print ('The IP addresses of the intermediate destination nodes: ')
	i = 1
	int_dest_list = sorted(int_dest.items(), key=itemgetter(1))
	for addr, ttl in int_dest_list:
		print ('      router {}: {}'.format(i, addr))
		i += 1

	print ('')
	protocols.sort()
	print ('The values in the protocol field of IP headers: ')
	for num, proto in protocols:
		print ('      {}. {}'.format(num, proto))