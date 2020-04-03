
from scapy.all import *
import sys, os
from myTimestamp_header import MyTimestamp

TYPE_MYMODE = 0x1233

class MyMode(Packet):
    name = "MyMode"
    fields_desc = [
        ShortField("cnt", 0)
    ]
    #def mysummary(self):
    #    return self.sprintf("tmp=%tmp%")


bind_layers(Ether, MyMode, type=TYPE_MYMODE)
bind_layers(MyMode, MyTimestamp)
bind_layers(MyTimestamp, IP)
