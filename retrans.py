import os
import struct
import fcntl
import pprint
import select
from pox.lib.packet import ipv4
from pox.lib.addresses import IPAddr
from pox.lib.packet import ICMP
from nat_wrapper import snat_wrapper


TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
host = IPAddr("10.170.0.2")
snat_wrapper.ip_pool([host])


def processICMP(pkt):
    req = pkt.next
    if pkt.dstip == host and req.type == ICMP.TYPE_ECHO_REQUEST:
        pkt.dstip = pkt.srcip
        pkt.srcip = host
        req.type = ICMP.TYPE_ECHO_REPLY
        size = os.write(tun, pkt.pack())
        print("write to eic %s bytes" % size)


tcp_nat_table = {}


def processTCP(pkt):
    print 'processing %s' % pkt.next
    sock = None
    try:
        sock = (pkt.srcip, pkt.next.srcport,
                pkt.dstip, pkt.next.dstport)
    except:
        with open("err.pkt", 'w+') as f:
            f.write(pkt.pack())

    wrapper = tcp_nat_table.get(sock)
    if wrapper is None:
        wrapper = snat_wrapper.new_wrapper(sock)
        if wrapper is not None:
            _, down = wrapper.get_socks()
            tcp_nat_table[sock] = wrapper
            tcp_nat_table[down] = wrapper

    if wrapper is not None:
        pkt_send = wrapper.consume(pkt)
        os.write(tun, pkt_send.pack())


def processUDP(pkt):
    print("incoming udp pkt")
    pass


def process(packet):
    pkt = ipv4.unpack(packet)

    if pkt.protocol == ipv4.ICMP_PROTOCOL:
        processICMP(pkt)
    elif pkt.protocol == ipv4.TCP_PROTOCOL:
        processTCP(pkt)
    elif pkt.protocol == ipv4.UDP_PROTOCOL:
        processUDP(pkt)


# Open TUN device file.
tun = os.open('/dev/net/tun', os.O_NONBLOCK | os.O_RDWR)

# Tall it we want a TUN device named tun0.
ifr = struct.pack('16sH', 'tun0', IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

while True:
    rlist, _, _ = select.select([tun], [], [], 0.02)

    if len(rlist) > 0:
        print ""
        try:
            while True:
                # Read an IP packet been sent to this TUN device.
                packet = os.read(tun, 2048)
                process(packet)
        except OSError as err:
            pass
    else:
        for s in tcp_nat_table.keys():
            c = tcp_nat_table[s]
            if c.is_time_out():
                print("clean sock: %s %s" % tcp_nat_table[s].get_socks())
                del tcp_nat_table[s]
            else:
                pkt = c.retrans(s)
                if pkt is not None:
                    os.write(tun, pkt.pack())
