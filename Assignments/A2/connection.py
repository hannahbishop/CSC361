import time

class _Connection():
    def __init__(self, src_addr, sport, dest_addr, dport):
        self.src_addr = src_addr
        self.sport = sport
        self.dest_addr = dest_addr
        self.dport = dport
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.packets = [0,0]
        self.bytes = [0,0]
        self.start_time = None
        self.end_time = None
        self.win = [0, 0]

    def __eq__(self, other):
        if (
            self.src_addr == other.src_addr and
            self.sport == other.sport and
            self.dest_addr == other.dest_addr and
            self.dport == other.dport
        ): 
            return True
        if (
            self.src_addr == other.dest_addr and
            self.sport == other.dport and
            self.dest_addr == other.src_addr and
            self.dport == other.sport
        ):
            return True
        return False
    
    def inc_syn(self, ts):
        self.syn += 1
        #only set the start time if it's the first SYN
        if self.syn == 1:
            self.start_time = ts
        return

    def inc_fin(self, ts):
        self.fin += 1
        #always update the end time
        self.end_time = ts
        return

    def set_rst(self):
        self.rst = 1

    def get_start_time(self):
        return self.start_time

    def get_end_time(self):
        return self.end_time

    def get_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return -1

    def is_complete(self):
        return self.syn and self.fin

    def get_rst(self):
        return self.rst

    def send_packet(self, src_addr, dest_addr, len, win):
        if src_addr == self.src_addr and dest_addr == self.dest_addr:
            self.packets[0] += 1
            self.bytes[0] += len
            self.win[0] = win
        else:
            self.packets[1] += 1
            self.bytes[1] += len
            self.win[1] = win
        return

    def get_num_packets(self):
        return sum(self.packets)

    def get_win(self):
        return self.win

    def print_data(self):
        print("Source Address: ", self.src_addr)
        print("Destination Address: ", self.dest_addr)
        print("Source Port: ", self.sport)
        print("Destination Port: ", self.dport)
        print("Status: S{}F{}".format(self.syn, self.fin))
        if self.start_time:
            print("Start Time: %.5f" % (self.start_time - 1139256717.834392))
        if self.end_time:
            print("End Time: %.5f" % (self.end_time - 1139256717.834392))
        if self.start_time and self.end_time:
            print("Total Duration: %.5f" % (self.end_time - self.start_time))
        print("Number of packets sent from Source to Destination: ", self.packets[0])
        print("Number of packets sent from Destination to Source: ", self.packets[1])
        print("Total number of packets: ", sum(self.packets))
        print("Number of bytes sent from Source to Destination: ", self.bytes[0])
        print("Number of bytes sent from Destination to Source: ", self.bytes[1])
        print("Total number of bytes: ", sum(self.bytes))