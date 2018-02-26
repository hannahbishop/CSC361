import time

class _Connection():
    def __init__(self, src_addr, sport, dest_addr, dport, flags):
        self.src_addr = src_addr
        self.sport = sport
        self.dest_addr = dest_addr
        self.dport = dport
        self.flags = flags
        self.syn = 0
        self.fin = 0
        self.start_time = None
        self.end_time = None

    def __eq__(self, other):
        equal = True
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
        else:
            return False

    def print(self):
        print(self.src_addr, self.sport, self.dest_addr, self.dport, self.flags)
        print(self.syn, self.fin)
        print(self.start_time, self.end_time, self.end_time - self.start_time)
        return
    
    def inc_syn(self, ts):
        if self.syn == 2:
            print("Cannot increment syn")
            return -1
        self.syn += 1
        #only set the start time if it's the first SYN
        if self.syn == 1:
            self.start_time = ts
        return

    def inc_fin(self, ts):
        if self.fin == 2:
            print("Cannot increment fin")
            return -1
        self.fin += 1
        #always update the end time
        self.end_time = ts
        return

    def get_start_time(self):
        return self.start_time

    def get_end_time(self):
        return self.end_time

    def get_duration(self):
        return self.end_time - self.start_time

    def is_complete(self):
        return self.start_time and self.end_time