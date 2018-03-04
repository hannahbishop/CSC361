import time

class _Connection():
    def __init__(self, src_addr, sport, dest_addr, dport, flags):
        self.src_addr = src_addr
        self.sport = sport
        self.dest_addr = dest_addr
        self.dport = dport
        self.syn = flags[0]
        self.fin = flags[1]
        self.start_time = None
        self.end_time = None
        self.reset = None

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

    def set_reset(self):
        self.reset == 1

    def get_start_time(self):
        return self.start_time

    def get_end_time(self):
        return self.end_time

    def get_duration(self):
        return self.end_time - self.start_time

    def is_complete(self):
        return self.syn and self.fin

    def print_data(self):
        print("Source Address: ", self.src_addr)
        print("Destination Address: ", self.dest_addr)
        print("Source Port: ", self.sport)
        print("Destination Port: ", self.dport)
        print("Status: S{}F{}".format(self.syn, self.fin))
        #print("Start Time: ", self.start_time)
        #print("End Time: ", self.end_time)
        #print("Total Duration: ", self.end_time - self.start_time)