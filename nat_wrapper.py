from tcp_conn import tcp_conn
import time


class snat_wrapper(object):
    pool = []
    nat_pair = {}

    @classmethod
    def ip_pool(cls, ips):
        cls.pool = ips

    @classmethod
    def new_wrapper(cls, sock):
        srcip, srcport, dstip, dstport = sock
        if cls.nat_pair.get(srcip) is not None or len(cls.pool) > 0:
            return snat_wrapper(sock)
        else:
            return None

    def __init__(self, sock):
        srcip, srcport, dstip, dstport = sock
        if not srcip in self.nat_pair:
            self.nat_pair[srcip] = self.pool.pop()

        self.srcip = self.nat_pair[srcip]
        self.orig_srcip = srcip
        self.dstip = dstip
        self.socks = ((srcip, srcport,
                       dstip, dstport),
                      (dstip, dstport,
                       self.srcip, srcport))

        self.conn = None

    def get_socks(self):
        return self.socks

    def consume(self, pkt):
        print("snat consume pkt: %s" % pkt)
        self.last_pkt = time.time()
        if self.conn is None:
            self.conn = tcp_conn.new_conn(pkt)
            return self.nat_pkt(pkt)

        else:
            if self.is_down_pkt(pkt):
                pkt = self.nat_pkt(pkt)
                self.conn.consume(pkt)
            else:
                self.conn.consume(pkt)
                pkt = self.nat_pkt(pkt)

            return pkt

    def nat_pkt(self, pkt):
        if pkt is None:
            return pkt

        if self.is_up_pkt(pkt):
            pkt.srcip = self.srcip
            return pkt
        else:
            pkt.dstip = self.orig_srcip
            return pkt

    def is_up_pkt(self, pkt):
        return pkt.dstip == self.dstip

    def is_down_pkt(self, pkt):
        return not self.is_up_pkt(pkt)

    def is_up_sock(self, sock):
        _, _, dstip, _ = sock
        return dstip == self.dstip

    def is_down_sock(self, sock):
        return not self.is_up_sock(sock)

    def is_time_out(self):
        return self.last_pkt + 60 * 3 <= time.time()

    def retrans(self, sock):
        if self.conn is not None:
            pkt = None
            if self.is_up_sock(sock):
                pkt = self.conn.retrans_client_pkt()
                return self.nat_pkt(pkt)
            else:
                pkt = self.conn.retrans_server_pkt()
                return pkt
