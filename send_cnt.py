#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import argparse
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from myMode_header import MyMode
from newTimestamp_header import newTimestamp

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

#sudo python send.py -s 10.0.1.1 -d 10.0.2.2 -m "sheng" -t 1 -n 1
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--src-ip', type=str, help="The source IP address to use")
    parser.add_argument('-d', '--dst-ip', type=str, help="The destination IP address to use")
    parser.add_argument('-m', '--message', type=str, help="The message to include in packet")
    parser.add_argument('-t', '--tmp', type=int, default=None, help='The timestamp to include in packet')
    parser.add_argument('-n', '--pkt-num', type=int, default=1, help='The num of packets to send')

    args = parser.parse_args()
    src = socket.gethostbyname(args.src_ip)
    dst = socket.gethostbyname(args.dst_ip)
    #print addr
    tmp = args.tmp
    iface = get_if()

    if (tmp is not None):
        print "sending on interface {} from IP addr {} to IP addr {} with timestamp {}".format(iface, str(src), str(dst), str(tmp))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:ff:00')
        pkt = pkt / newTimestamp(ptp=tmp) / IP(src=src, dst=dst) / args.message
    else:
        print "sending on interface {} from IP addr {} to IP addr {}".format(iface, str(src), str(dst))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:ff:00')
        pkt = pkt / IP(src=src, dst=dst) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message

    pkt.show()
    hexdump(pkt)
    print "len(pkt) = ", len(pkt)
    #sendp(pkt, iface=iface, verbose=False)

    pkt_num = args.pkt_num
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('eth0', 0))
    start_time = time.time()
    delay = 0.001
    for i in range(pkt_num):
        #sendp(p, iface='h%d-eth0' %src)
        #msg = "Sheng!" + str(i)
        s.send(str(pkt))
        #print len(str(p))
        #print str(p)[46:]
        #hexdump(p)
        #print p.show()
        #print struct.unpack("!I", str(p)[62:66])[0]
        #print int(str(p)[62:66],16)
        time.sleep(delay)
    print "sent" + str(pkt_num)
    print time.time() - start_time


if __name__ == '__main__':

    main()
