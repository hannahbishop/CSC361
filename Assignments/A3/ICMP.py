from IP import _IP

class _ICMP(_IP):
    def __init__(self, src, dst, ts, ttl, p, seq):
        _IP.__init__(self, src, dst, ts, ttl, p)
        self.seq = seq
