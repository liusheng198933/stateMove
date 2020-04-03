
from scapy.all import *
import sys, os

TYPE_MYTMP = 0x1212
TYPE_IPV4 = 0x0800

class newTimestamp(Packet):
    name = "newTimestamp"
    fields_desc = [
        BitField("ptp", 0, 16),
        BitField("rtp", 0, 16),
        BitField("ttp", 0, 16),
        IntField("fid", 0)
    ]


bind_layers(Ether, newTimestamp, type=TYPE_MYTMP)
bind_layers(newTimestamp, IP)
