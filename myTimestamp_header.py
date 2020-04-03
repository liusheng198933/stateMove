
from scapy.all import *
import sys, os

TYPE_MYTMP = 0x1212
TYPE_IPV4 = 0x0800

class MyTimestamp(Packet):
    name = "MyTimestamp"
    fields_desc = [
        ShortField("tmp", 0)
    ]
    def mysummary(self):
        return self.sprintf("tmp=%tmp%")


bind_layers(Ether, MyTimestamp, type=TYPE_MYTMP)
bind_layers(MyTimestamp, IP)
