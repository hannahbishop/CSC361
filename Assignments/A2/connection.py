class _Connection():
    def __init__(self, src_addr, sport, dest_addr, dport, flags):
        self.src_addr = src_addr
        self.sport = sport
        self.dest_addr = dest_addr
        self.dport = dport
        self.flags = flags
        self.syn = 0
        self.fin = 0

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

    def __repr__(self):
        return "Item(%s, %s)" % (self.foo, self.bar)

    def print(self):
        print(self.src_addr, self.sport, self.dest_addr, self.dport, self.flags)
        print(self.syn, self.fin)
        return
    
    def inc_syn(self):
        if self.syn == 2:
            print("Cannot increment syn")
            return -1
        self.syn += 1
        return

    def inc_fin(self):
        if self.fin == 2:
            print("Cannot increment fin")
            return -1
        self.fin += 1
        return
    