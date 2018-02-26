class _Connection():
    def __init__(self, src_addr, sport, dest_addr, dport, flags):
        self.src_addr = src_addr
        self.sport = sport
        self.dest_addr = dest_addr
        self.dport = dport
        self.flags = flags

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
    