from pox.lib.packet import ipv4, tcp
import time


class timer_pkt(object):
    def __init__(self, pkt):
        """
        """
        self.pkt = pkt
        self.time_stamp = time.time()

    def __getattr__(self, name):
        return getattr(self.pkt, name)


class tcp_conn(object):
    SYN_RCVD = 1
    CLI_EST = 2
    ESTABLISHED = 3
    CLOSING = 4
    CLOSED = 5

    def __init__(self, pkt):
        if pkt.next.flags == tcp.SYN_flag:
            self.clientip = pkt.srcip
            self.serverip = pkt.dstip
            self.clientport = pkt.next.srcport
            self.serverport = pkt.next.dstport
            self.clientseq = None
            self.serverseq = None
            self.client_stream = []
            self.server_stream = []
            self.client_close = False
            self.server_close = False
            self.update_stream_from_client(pkt)
            self.state = self.SYN_RCVD
            self.process = self.syn_rcvd

    def consume(self, pkt):
        """
        todo:
        handle abnormal case
        """
        print("consume pkt %s" % pkt.next)
        if pkt.next.RST:
            self.server_stream = []
            self.client_stream = []
        else:
            if hasattr(self, 'process'):
                self.process(pkt)

    def syn_rcvd(self, pkt):
        if self.pkt_from_server(pkt):
            self.update_stream_from_server(pkt)
            if pkt.next.SYN and pkt.next.ACK:
                self.state = self.CLI_EST
                self.process = self.cli_est
        else:
            self.update_stream_from_client(pkt)

    def cli_est(self, pkt):
        if self.pkt_from_client(pkt):
            self.update_stream_from_client(pkt)
            if pkt.next.ACK and not pkt.next.SYN:
                self.state = self.ESTABLISHED
                self.process = self.established
        else:
            self.update_stream_from_server(pkt)

    def established(self, pkt):
        if self.pkt_from_client(pkt):
            if pkt.next.FIN:
                self.client_stream = []
                self.state = self.CLOSING
                self.process = self.closing
                self.client_close = True
            else:
                self.update_stream_from_client(pkt)
        else:
            if pkt.next.FIN:
                self.server_stream = []
                self.state = self.CLOSING
                self.process = self.closing
                self.server_close = True
            else:
                self.update_stream_from_server(pkt)

    def closing(self, pkt):
        self.client_stream, self.server_stream = [], []
        if self.pkt_from_client(pkt):
            self.client_close = self.client_close or pkt.next.FIN
        else:
            self.server_close = self.server_close or pkt.next.FIN

        if (self.is_empty_stream(self.client_stream, self.clientseq) and
            self.is_empty_stream(self.server_stream, self.serverseq) and
            self.client_close and self.server_close):
            self.state = self.CLOSED
            self.process = self.closed

    def closed(self, pkt):
        pass

    def pkt_from_client(self, pkt):
        return (pkt.dstip == self.serverip and pkt.srcip == self.clientip and
                pkt.next.dstport == self.serverport and
                pkt.next.srcport == self.clientport)

    def pkt_from_server(self, pkt):
        return (pkt.srcip == self.serverip and pkt.dstip == self.clientip and
                pkt.next.srcport == self.serverport and
                pkt.next.dstport == self.clientport)

    def update_stream_from_server(self, pkt):
        if pkt.next.ACK:
            self.ack_client_stream(pkt.next.ack)
        print("acked seq %s" % self.serverseq)
        self.server_stream = self.append_stream(
            self.server_stream, timer_pkt(pkt))

    def update_stream_from_client(self, pkt):
        if pkt.next.ACK:
            self.ack_server_stream(pkt.next.ack)
        print("acked seq %s" % self.clientseq)
        self.client_stream = self.append_stream(
            self.client_stream, timer_pkt(pkt))

    def append_stream(self, stream, pkt):
        self.print_stream(stream)
        new_stream = filter(lambda p: p.next.seq != pkt.next.seq, stream)
        new_stream = filter(lambda p: (self.expect_ack(p) <= pkt.next.seq or
                                  p.next.seq >= self.expect_ack(pkt)), new_stream)
        ind = next((i for i in range(len(new_stream))
                    if new_stream[i].next.seq > pkt.next.seq), 0)
        new_stream.insert(ind, pkt)
        self.print_stream(new_stream)

        return new_stream

    def ack_client_stream(self, ack):
        valid, stream = self.ack_stream(self.client_stream, ack)
        if valid:

            self.clientseq = ack
            self.client_stream = stream
            return True
        else:
            return self.clientseq == ack

    def ack_server_stream(self, ack):
        valid, stream = self.ack_stream(self.server_stream, ack)
        print("ack server stream %s %s" % (valid, stream))

        if valid:
            self.serverseq = ack
            self.server_stream = stream
            return True
        else:
            return self.serverseq == ack

    def ack_stream(self, stream, ack):
        if len(stream) > 0:
            target = None
            print([self.expect_ack(pkt) for pkt in stream], ack)
            for target in (pkt for pkt in stream
                           if self.expect_ack(pkt) == ack):
                pass
            while target is not None and stream[0] != target:
                stream = stream[1:]

            if target is not None:
                stream = stream[1:]
                return True, stream
            else:
                return False, stream
        else:
            return True, []

    def print_stream(self, stream):
        print(" ".join(('%s@%s' % (str(p.next), p.time_stamp)) for p in stream))

    def expect_ack(self, pkt):
        return (pkt.next.seq + pkt.next.payload_len +
                (1 if pkt.next.SYN or pkt.next.FIN else 0))

    def is_empty_stream(self, stream, seq):
        return all(seq == self.expect_ack(pkt) for pkt in stream)

    def __str__(self):
        ret = ['clientip', 'clientport', 'serverip', 'serverport',
               'clientseq', 'client_stream', 'serverseq', 'server_stream',
               'client_close', 'server_close', 'state']

        def add_hash(h, a):
            h[a] = getattr(self, a)
            return h
        return str(reduce(lambda h, a: add_hash(h, a), ret, {}))

    def retrans_client_pkt(self):
        pkt = self.retrans_pkt(self.client_stream, self.clientseq)
        if pkt is not None:
            pkt.time_stamp = time.time()
        return pkt

    def retrans_server_pkt(self):
        pkt = self.retrans_pkt(self.server_stream, self.serverseq)
        if pkt is not None:
            pkt.time_stamp = time.time()

        return pkt

    def retrans_pkt(self, stream, seq):
        now = time.time()
        return next((pkt for pkt in stream
                     if ((seq is None or pkt.next.seq == seq) and
                         now - pkt.time_stamp > 0.02)), None)

    @classmethod
    def new_conn(cls, pkt):
        if pkt.protocol == ipv4.TCP_PROTOCOL:
            conn = cls(pkt)
            if hasattr(conn, 'state') and conn.state == cls.SYN_RCVD:
                return conn
        else:
            return None
