from IP import _IP

class _UDP(_IP):
    def __init__(self, src, dst, ts, ttl, p, sport, dport):
        _IP.__init__(self, src, dst, ts, ttl, p)
        self.sport = sport
        self.dport = dport