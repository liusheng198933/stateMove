#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from newTimestamp_header import newTimestamp
from myMode_header import MyMode

pkt_num = 0

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def handle_pkt(pkt):
    global pkt_num
    if newTimestamp in pkt:
        # or (TCP in pkt and pkt[TCP].dport == 1234):
        #print "got a packet"
        pkt_num += 1
        #pkt.show2()
        #print pkt[Ether]
        #hexdump(pkt)
        #print "len(pkt) = ", len(pkt)
        #sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface, timeout = 10,
          prn = lambda x: handle_pkt(x))
    print "received packets: %d" %pkt_num

if __name__ == '__main__':
    main()
