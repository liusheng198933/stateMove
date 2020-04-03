#!/usr/bin/env python2
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse
import json
import os
import sys

import bmv2
import helper
import convert
import random
import threading
from time import sleep
from scc.algorithm import *
from mininet.cli import CLI
from scc.switch_state import rule, net, table

priority_default = 1

def error(msg):
    print >> sys.stderr, ' - ERROR! ' + msg

def info(msg):
    print >> sys.stdout, ' - ' + msg


class ConfException(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description='P4Runtime Simple Controller')

    parser.add_argument('-a', '--p4runtime-server-addr',
                        help='address and port of the switch\'s P4Runtime server (e.g. 192.168.0.1:50051)',
                        type=str, action="store", required=True)
    parser.add_argument('-d', '--device-id',
                        help='Internal device ID to use in P4Runtime messages',
                        type=int, action="store", required=True)
    parser.add_argument('-p', '--proto-dump-file',
                        help='path to file where to dump protobuf messages sent to the switch',
                        type=str, action="store", required=True)
    parser.add_argument("-c", '--runtime-conf-file',
                        help="path to input runtime configuration file (JSON)",
                        type=str, action="store", required=True)

    args = parser.parse_args()

    if not os.path.exists(args.runtime_conf_file):
        parser.error("File %s does not exist!" % args.runtime_conf_file)
    workdir = os.path.dirname(os.path.abspath(args.runtime_conf_file))
    with open(args.runtime_conf_file, 'r') as sw_conf_file:
        program_switch(addr=args.p4runtime_server_addr,
                       device_id=args.device_id,
                       sw_conf_file=sw_conf_file,
                       workdir=workdir,
                       proto_dump_fpath=args.proto_dump_file)


def check_switch_conf(sw_conf, workdir):
    required_keys = ["p4info"]
    files_to_check = ["p4info"]
    target_choices = ["bmv2"]

    if "target" not in sw_conf:
        raise ConfException("missing key 'target'")
    target = sw_conf['target']
    if target not in target_choices:
        raise ConfException("unknown target '%s'" % target)

    if target == 'bmv2':
        required_keys.append("bmv2_json")
        files_to_check.append("bmv2_json")

    for conf_key in required_keys:
        if conf_key not in sw_conf or len(sw_conf[conf_key]) == 0:
            raise ConfException("missing key '%s' or empty value" % conf_key)

    for conf_key in files_to_check:
        real_path = os.path.join(workdir, sw_conf[conf_key])
        if not os.path.exists(real_path):
            raise ConfException("file does not exist %s" % real_path)


def configure_switch(sw_name, addr, device_id, p4info_helper, bmv2_json_fpath, proto_dump_fpath=None):

    #info('Configure P4 switch')
    #p4info_helper = helper.P4InfoHelper(p4info_fpath)


    #info("Connecting to P4Runtime server on %s..." % addr)

    if proto_dump_fpath:
        sw = bmv2.Bmv2SwitchConnection(name=sw_name, address=addr, device_id=device_id,
                                        proto_dump_file=proto_dump_fpath)
    else:
        sw = bmv2.Bmv2SwitchConnection(name=sw_name, address=addr, device_id=device_id)

    try:
        sw.MasterArbitrationUpdate()

        #info("Setting pipeline config")
        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_fpath)
        return sw
    except:
        sw.shutdown()


def shutdown_connection(sw):
    #sw = bmv2.Bmv2SwitchConnection(address=addr, device_id=device_id)
    sw.shutdown()


def program_switch(addr, device_id, sw_conf_file, workdir, proto_dump_fpath):
    sw_conf = json_load_byteified(sw_conf_file)
    try:
        check_switch_conf(sw_conf=sw_conf, workdir=workdir)
    except ConfException as e:
        error("While parsing input runtime configuration: %s" % str(e))
        return

    info('Using P4Info file %s...' % sw_conf['p4info'])
    p4info_fpath = os.path.join(workdir, sw_conf['p4info'])
    p4info_helper = helper.P4InfoHelper(p4info_fpath)

    target = sw_conf['target']

    info("Connecting to P4Runtime server on %s (%s)..." % (addr, target))

    if target == "bmv2":
        sw = bmv2.Bmv2SwitchConnection(address=addr, device_id=device_id,
                                       proto_dump_file=proto_dump_fpath)
    else:
        raise Exception("Don't know how to connect to target %s" % target)

    try:
        sw.MasterArbitrationUpdate()

        if target == "bmv2":
            info("Setting pipeline config (%s)..." % sw_conf['bmv2_json'])
            bmv2_json_fpath = os.path.join(workdir, sw_conf['bmv2_json'])
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_fpath)
        else:
            raise Exception("Should not be here")

        if 'table_entries' in sw_conf:
            table_entries = sw_conf['table_entries']
            info("Inserting %d table entries..." % len(table_entries))
            for entry in table_entries:
                info(tableEntryToString(entry))
                insertTableEntry(sw, entry, p4info_helper)

        if 'multicast_group_entries' in sw_conf:
            group_entries = sw_conf['multicast_group_entries']
            info("Inserting %d group entries..." % len(group_entries))
            for entry in group_entries:
                info(groupEntryToString(entry))
                insertMulticastGroupEntry(sw, entry, p4info_helper)

    finally:
        sw.shutdown()


def table_entry_construct(p4info_helper, src_ip_addr, src_addr_mask, dst_ip_addr, dst_addr_mask, dst_mac_addr, rtmp, ttmp, out_port, flow_id=0, priority=priority_default):
    #print dst_mac_addr
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.srcAddr": (src_ip_addr, src_addr_mask),
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_addr_mask)
        },
        priority=priority,
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr,
            "port": out_port,
            "rtmp": rtmp,
            "ttmp": ttmp,
            "flowid": flow_id
        })

    return table_entry


def table_entry_construct_state(p4info_helper, src_ip_addr, src_addr_mask, dst_ip_addr, dst_addr_mask, flow_id, priority=priority_default):
    #print dst_mac_addr
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.srcAddr": (src_ip_addr, src_addr_mask),
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_addr_mask)
        },
        priority=priority,
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr,
            "port": out_port,
            "rtmp": rtmp,
            "ttmp": ttmp,
            "flowid": flow_id
        })

    return table_entry


def insertTableEntry(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action') # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)

    sw.WriteTableEntry(table_entry)


def path_deploy(p4info_helper, old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dstAddr_dic, clk, topo_net, sw_conn, flow_id=0):
    rule_deploy = rule_construct_scc(old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dstAddr_dic, clk, flow_id)
    for step in range(len(rule_deploy)):
        rule_set = rule_deploy[step]
        print "new step %d starts" %step

        print "rules to be deleted:"
        for s in rule_set:
            for r in rule_set[s]['del']:
                r.print_rule()

        print "rules to be added:"
        for s in rule_set:
            for r in rule_set[s]['add']:
                r.print_rule()

        # for sw_name in rule_set:
        #     print sw_name
        #     switch_deploy_delay(p4info_helper, sw_conn[sw_name], rule_set[sw_name])

        thread_list = []
        for sw_name in rule_set:
            thread_list.append(switch_deploy_delay(p4info_helper, sw_conn[sw_name], rule_set[sw_name], sw_name))
        for thd in thread_list:
            thd.join()
        print "new step %d completed" %step




def switch_deploy_delay(p4info_helper, sw, sw_rule, sw_name=None):

    src_ip_addr_list = []
    src_addr_mask_list = []
    dst_ip_addr_list = []
    dst_addr_mask_list = []
    dst_mac_addr_list = []
    rtmp_list = []
    ttmp_list = []
    out_port_list= []
    flow_id_list= []
    priority_list = []
    update_flag_write_list = []

    for r in sw_rule['del']:
        mt = r.get_match()
        #print "sw_name: %s" %sw_name
        #print mt['ipv4_dst']
        #print mt['ipv4_src']
        if not mt:
            dst_ip_addr_list.append('0.0.0.0')
            dst_addr_mask_list.append('0.0.0.0')
            src_ip_addr_list.append('0.0.0.0')
            src_addr_mask_list.append('0.0.0.0')
        else:
            dst_ip_addr_list.append(mt['ipv4_dst'])
            dst_addr_mask_list.append(mt['mask_dst'])
            src_ip_addr_list.append(mt['ipv4_src'])
            src_addr_mask_list.append(mt['mask_src'])
        dst_mac_addr_list.append(r.get_dst_mac())
        rtmp_list.append(r.get_rtmp())
        ttmp_list.append(r.get_ttmp())
        out_port_list.append(r.get_action())
        flow_id_list.append(r.get_flow_id())
        priority_list.append(r.get_prt())
        update_flag_write_list.append(1)

    for r in sw_rule['add']:
        mt = r.get_match()
        #print "dp: %d" %dp
        #print mt['ipv4_dst']
        #print mt['ipv4_src']
        if not mt:
            dst_ip_addr_list.append('0.0.0.0')
            dst_addr_mask_list.append('0.0.0.0')
            src_ip_addr_list.append('0.0.0.0')
            src_addr_mask_list.append('0.0.0.0')
        else:
            dst_ip_addr_list.append(mt['ipv4_dst'])
            dst_addr_mask_list.append(mt['mask_dst'])
            src_ip_addr_list.append(mt['ipv4_src'])
            src_addr_mask_list.append(mt['mask_src'])
        dst_mac_addr_list.append(r.get_dst_mac())
        rtmp_list.append(r.get_rtmp())
        ttmp_list.append(r.get_ttmp())
        out_port_list.append(r.get_action())
        flow_id_list.append(r.get_flow_id())
        priority_list.append(r.get_prt())
        update_flag_write_list.append(0)

    delay = random.normalvariate(150, 50) / 1000
    while delay <= 0:
        delay = random.normalvariate(150, 50) / 1000

    print sw_name
    print delay
    #print flow_id_list
    # print update_flag_write_list
    # writeMultiRules(p4info_helper, sw,
    #                  src_ip_addr_list, src_addr_mask_list,
    #                  dst_ip_addr_list, dst_addr_mask_list,
    #                  dst_mac_addr_list, rtmp_list, ttmp_list, out_port_list,
    #                  flow_id_list, priority_list, update_flag_write_list)


    thread = writeThread(p4info_helper, sw, src_ip_addr_list, src_addr_mask_list,
                    dst_ip_addr_list, dst_addr_mask_list, dst_mac_addr_list, rtmp_list, ttmp_list,
                    out_port_list, flow_id_list, priority_list, update_flag_write_list, delay)

    thread.start()

    return thread


class writeThread (threading.Thread):
   def __init__(self, p4info_helper, sw, src_ip_addr_list, src_addr_mask_list, dst_ip_addr_list, dst_addr_mask_list, dst_mac_addr_list, rtmp_list, ttmp_list, out_port_list, flow_id_list, priority_list, update_flag_write_list, delay=0):
      threading.Thread.__init__(self)
      self.p4info_helper = p4info_helper
      self.sw = sw
      self.src_ip_addr_list = src_ip_addr_list
      self.src_addr_mask_list = src_addr_mask_list
      self.dst_ip_addr_list = dst_ip_addr_list
      self.dst_addr_mask_list =  dst_addr_mask_list
      self.rtmp_list = rtmp_list
      self.ttmp_list = ttmp_list
      self.out_port_list = out_port_list
      self.dst_mac_addr_list = dst_mac_addr_list
      self.flow_id_list = flow_id_list
      self.priority_list = priority_list
      self.update_flag_write_list = update_flag_write_list
      self.delay = delay

   def run(self):
       if self.delay:
           sleep(self.delay)
       writeMultiRules(self.p4info_helper, self.sw,
                        self.src_ip_addr_list, self.src_addr_mask_list,
                        self.dst_ip_addr_list, self.dst_addr_mask_list,
                        self.dst_mac_addr_list, self.rtmp_list, self.ttmp_list, self.out_port_list,
                        self.flow_id_list, self.priority_list, self.update_flag_write_list)


def writeMultiRules(p4info_helper, sw, src_ip_addr_list, src_addr_mask_list,
                    dst_ip_addr_list, dst_addr_mask_list, dst_mac_addr_list, rtmp_list, ttmp_list,
                    out_port_list, flow_id_list, priority_list, update_flag_write_list):
    # the rule of priority: smaller is more priority

    for i in range(len(dst_ip_addr_list)):
        #print sw_id
        #print update_flag_write_list[i]
        table_entry = table_entry_construct(p4info_helper, src_ip_addr_list[i], src_addr_mask_list[i],
                                            dst_ip_addr_list[i], dst_addr_mask_list[i], dst_mac_addr_list[i],
                                            rtmp_list[i], ttmp_list[i], out_port_list[i], flow_id_list[i], priority_list[i])

        sw.WriteTableEntry(table_entry=table_entry, update_flag=update_flag_write_list[i])

    #print "Installed multiple rules on %s" % sw.name


def readTableEntry(sw, p4info_helper):
    '''
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    '''

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
                    print '%r' % (convert.decodeIPv4(p4info_helper.get_match_field_value(m)[0]),),
                elif "Addr" in mname:
                    print '%r' % (convert.decodeMac(p4info_helper.get_match_field_value(m)),),
                elif "port" in mname:
                    print '%r' % (convert.decodeNum(p4info_helper.get_match_field_value(m)),),
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


# object hook for josn library, use str instead of unicode object
# https://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-of-unicode-from-json
def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify),
                    ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data


def tableEntryToString(flow):
    if 'match' in flow:
        match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for match_name in
                     flow['match']]
        match_str = ', '.join(match_str)
    elif 'default_action' in flow and flow['default_action']:
        match_str = '(default action)'
    else:
        match_str = '(any)'
    params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
              flow['action_params']]
    params = ', '.join(params)
    return "%s: %s => %s(%s)" % (
        flow['table'], match_str, flow['action_name'], params)


def groupEntryToString(rule):
    group_id = rule["multicast_group_id"]
    replicas = ['%d' % replica["egress_port"] for replica in rule['replicas']]
    ports_str = ', '.join(replicas)
    return 'Group {0} => ({1})'.format(group_id, ports_str)

def insertMulticastGroupEntry(sw, rule, p4info_helper):
    mc_entry = p4info_helper.buildMulticastGroupEntry(rule["multicast_group_id"], rule['replicas'])
    sw.WriteMulticastGroupEntry(mc_entry)


if __name__ == '__main__':
    #main()

    state = net()
    old_path = ['h_1', 's1', 's2', 's3', 's4', 's5', 'h_5']
    new_path = ['h_1', 's1', 's2', 's6', 's4', 's5', 'h_5']
    out_port_old = {'s1': 2, 's2': 2, 's3': 2, 's4': 2, 's5': 2}
    out_port_new = {'s1': 2, 's2': 3, 's6': 2, 's4': 2, 's5': 2}
    in_port_old = {'s1': 1, 's2': 1, 's3': 1, 's4': 1, 's5': 1}
    dstAddr_dic = {'h_1': "08:00:00:00:01:01",
                   'h_5': "08:00:00:00:05:05",
                   's1': "08:00:00:00:01:00",
                   's2': "08:00:00:00:02:00",
                   's3': "08:00:00:00:03:00",
                   's4': "08:00:00:00:04:00",
                   's5': "08:00:00:00:05:00",
                   's6': "08:00:00:00:06:00"}
    prt = 2
    clk = 7
    for i in set(old_path[1:-1] + new_path[1:-1]):
        state.add_table(i, 0)
    match = {}
    match["ipv4_src"] = "10.0.1.0"
    match["mask_src"] = "255.255.255.0"
    match["ipv4_dst"] = "10.0.5.0"
    match["mask_dst"] = "255.255.255.0"
    flow_id = 2

    path_deploy(self.p4info_helper, [], old_path, match, state, prt, {}, out_port_old, {}, dstAddr_dic, clk, flow_id)
