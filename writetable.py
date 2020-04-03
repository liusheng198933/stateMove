import sys
import p4runtime_lib.bmv2
import p4runtime_lib.helper
import p4runtime_lib.convert
import argparse
import os
from time import sleep
from scapy.all import Ether, IP, UDP, TCP
import random

def writeTableRules(p4info, sw_name):
    '''
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    '''
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)

    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name, address='127.0.0.1:%d' %(int(sw_name[1:])+50050))

    sw.MasterArbitrationUpdate()

    sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path='./build/basic.json')

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ('10.0.2.0', '255.255.255.0')
        },
        priority=1,
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": '08:00:00:00:02:02',
            "port": 2,
            "rtmp": 2,
            "ttmp": 2
        })

    sw.WriteTableEntry(table_entry)

    sw.shutdown()


def writeStateTableRules(p4info, sw_name):
    '''
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    '''
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)

    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name, address='127.0.0.1:%d' %(int(sw_name[1:])+50050))

    sw.MasterArbitrationUpdate()

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.state_migration",
        match_fields={
            "hdr.ipv4.dstAddr": ('10.0.2.0', '255.255.255.0')
        },
        priority=3,
        action_name="MyIngress.import_state")

    sw.WriteTableEntry(table_entry)

    sw.shutdown()


def packetOut(p4info, sw_name):
    '''
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    '''
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)



    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name,
                                                address='127.0.0.1:%d' %(int(sw_name[1:])+50050),
                                                device_id=int(sw_name[1:])-1,
                                                proto_dump_file='logs/%s-p4runtime-requests.txt' %sw_name)

    sw.MasterArbitrationUpdate()

    print "packet out"

    pkt =  Ether(src='08:00:00:00:01:00', dst='08:00:00:00:ff:00')
    pkt = pkt / IP(src="10.0.1.1", dst="10.0.2.2") / TCP(dport=1234, sport=random.randint(49152,65535)) / "packet out"

    sw.packet_out(pkt)
    sleep(1)

    sw.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Read Rules')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default="./build/basic.p4.p4info.txt")
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default="./build/basic.json")
    #parser.add_argument('--k', help='topo number',
    #                    type=int, action="store", required=False,
    #                    default=4)
    parser.add_argument('--swname', help='switch name',
                        type=str, action="store", required=True)
    #parser.add_argument('--flag', help='if fat tree',
    #                    type=int, action="store", required=False,
    #                    default=0)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)


    #writeTableRules(args.p4info, args.swname)

    #packetOut(args.p4info, args.swname)

    writeStateTableRules(args.p4info, args.swname)
