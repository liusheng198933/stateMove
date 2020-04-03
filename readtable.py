import sys
import p4runtime_lib.bmv2
import p4runtime_lib.helper
import p4runtime_lib.convert
import argparse
import os


def readTableRules(p4info, sw_name):
    '''
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    '''
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info)

    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name, address='localhost:%d' %(int(sw_name[1:])+50050), device_id=int(sw_name[1:]))
    #else:
    #    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(grpc2name(K, sw_id), address='localhost:%d' %(sw_id+50051))

    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                mname = p4info_helper.get_match_field_name(table_name, m.field_id)
                print mname,

                if "ipv4" in mname:
                    print '%r' % (p4runtime_lib.convert.decodeIPv4(p4info_helper.get_match_field_value(m)[0]),),
                elif "Addr" in mname:
                    print '%r' % (p4runtime_lib.convert.decodeMac(p4info_helper.get_match_field_value(m)),),
                elif "port" in mname:
                    print '%r' % (p4runtime_lib.convert.decodeNum(p4info_helper.get_match_field_value(m)),),
                else:
                    print '%r' % (p4info_helper.get_match_field_value(m),),
            print 'prt:%d' % entry.priority,
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print



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


    readTableRules(args.p4info, args.swname)
