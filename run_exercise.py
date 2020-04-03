#!/usr/bin/env python2
# Copyright 2013-present Barefoot Networks, Inc.
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
# Adapted by Robert MacDavid (macdavid@cs.princeton.edu) from scripts found in
# the p4app repository (https://github.com/p4lang/p4app)
#
# We encourage you to dissect this script to better understand the BMv2/Mininet
# environment used by the P4 tutorial.
#
import os, sys, json, subprocess, re, argparse
from time import sleep

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from scc.switch_state import net, table, rule

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.iteritems():
            if "program" in params:
                switchClass = configureP4Switch(
                        sw_path=bmv2_exe,
                        json_path=params["program"],
                        log_console=True,
                        pcap_dump=pcap_dir)
            else:
                # add default switch
                switchClass = None
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw), cls=switchClass)

        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                        port1=sw1_port, port2=sw2_port,
                        delay=link['latency'], bw=link['bandwidth'])


    def parse_switch_node(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port


class SingleSwitchTopo(Topo):
    """ The mininet topology class for one single switch.
    """
    def __init__(self, host_num, log_dir, **opts):
        Topo.__init__(self, **opts)
        self.sw_port_mapping = {}
        self.hosts_dic = []
        self.switches_dic = []

        sw_name = 's1'
        self.addSwitch(sw_name, log_file="%s/%s.log" %(log_dir, sw_name))
        self.switches_dic.append(sw_name)

        for i in range(host_num):
            host_name = 'h_%d' %(i+1)
            self.addHost(host_name, ip='10.0.%d.%d/24' %(i+1, i+1), mac='08:00:00:00:%02x:%02x' %(i+1, i+1))
            self.hosts_dic.append(host_name)
            self.addLink(host_name, sw_name)
            self.addSwitchPort(sw_name, host_name)



    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = {}
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw][node2] = portno


class LineSwitchTopo(Topo):
    """ The mininet topology class for one single switch.
    """
    def __init__(self, sw_num, log_dir, **opts):
        Topo.__init__(self, **opts)
        self.sw_port_mapping = {}
        self.hosts_dic = []
        self.switches_dic = []

        for i in range(1, sw_num+1):
            sw_name = 's%d' %i
            self.addSwitch(sw_name, log_file="%s/%s.log" %(log_dir, sw_name))
            self.switches_dic.append(sw_name)
            if i == 1:
                host_name = 'h_%d' %i
                self.addHost(host_name, ip='10.0.%d.%d/24' %(i, i), mac='08:00:00:00:%02x:%02x' %(i, i))
                self.hosts_dic.append(host_name)
                self.addLink(host_name, sw_name)
                self.addSwitchPort(sw_name, host_name)
            else:
                pre_name = 's%d' %(i-1)
                self.addLink(pre_name, sw_name)
                self.addSwitchPort(pre_name, sw_name)
                self.addSwitchPort(sw_name, pre_name)


        i = 2
        host_name = 'h_%d' %i
        self.addHost(host_name, ip='10.0.%d.%d/24' %(i, i), mac='08:00:00:00:%02x:%02x' %(i, i))
        self.hosts_dic.append(host_name)
        self.addLink(host_name, 's%d' %sw_num)
        self.addSwitchPort('s%d' %sw_num, host_name)


    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = {}
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw][node2] = portno

class TwoPathTopo(Topo):
    """ The mininet topology class for two paths, path1 and path2.
    """
    def __init__(self, log_dir, path1, path2, **opts):
        Topo.__init__(self, **opts)
        self.sw_port_mapping = {}
        self.hosts_dic = []
        self.switches_dic = []

        #path1 = ['s1', 's2', 's3', 's4', 's5']
        #path2 = ['s1', 's2', 's6', 's4', 's5']
        for sw_name in set(path1[1:-1] + path2[1:-1]):
            #self.addSwitch(sw_name)
            self.addSwitch(sw_name, log_file="%s/%s.log" %(log_dir, sw_name))
            self.switches_dic.append(sw_name)

        for i in range(1, len(path1)-2):
            self.addLink(path1[i], path1[i+1])
            self.addSwitchPort(path1[i], path1[i+1])
            self.addSwitchPort(path1[i+1], path1[i])

        for i in range(1, len(path2)-2):
            if path2[i+1] not in self.sw_port_mapping[path2[i]]:
                self.addLink(path2[i], path2[i+1])
                self.addSwitchPort(path2[i], path2[i+1])
                self.addSwitchPort(path2[i+1], path2[i])

        host_name = path1[0]
        i = int(host_name[2:])
        #print host_name
        self.addHost(host_name, ip='10.0.%d.%d/24' %(i, i), mac='08:00:00:00:%02x:%02x' %(i, i))
        self.hosts_dic.append(host_name)
        self.addLink(host_name, 's1')
        self.addSwitchPort('s1', host_name)

        host_name = path1[-1]
        i = int(host_name[2:])
        self.addHost(host_name, ip='10.0.%d.%d/24' %(i, i), mac='08:00:00:00:%02x:%02x' %(i, i))
        self.hosts_dic.append(host_name)
        self.addLink(host_name, 's5')
        self.addSwitchPort('s5', host_name)



    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = {}
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw][node2] = portno


class FatTree( Topo ):

    def __init__(self, K, **opts):

        # Topology settings
        self.podNum = K                      # Pod number in FatTree
        self.coreSwitchNum = pow((K/2),2)    # Core switches
        self.aggrSwitchNum = ((K/2)*K)       # Aggregation switches
        self.edgeSwitchNum = ((K/2)*K)       # Edge switches
        self.hostNum = (K*pow((K/2),2))      # Hosts in K-ary FatTree

        # Initialize topology
        Topo.__init__(self, **opts)

        self.coreSwitches = []
        self.aggrSwitches = []
        self.edgeSwitches = []
        self.sw_port_mapping = {}
        self.hosts_dic = []

        #arpSwitch = self.addSwitch("arp0", dpid='1'*7)
        # the format of switch dpid is 1-bit for switch classification, 3-bit for pod number and 3-bit for aggr or edge number
        # Core
        for core in range(self.coreSwitchNum):
            sw_name = 'cs_%d' %core
            self.addSwitch(sw_name)
            self.coreSwitches.append(sw_name)

            #coreSwitches.append(self.addSwitch("cs_"+str(core)))
            #coreSwitches.append(self.addSwitch("cs_"+str(core), dpid=int2dpid(1, core), protocols='OpenFlow14'))
        # Pod
        for pod in range(self.podNum):
        # Aggregate
            for aggr in range(self.aggrSwitchNum/self.podNum):
                aggrThis = 'as_%d_%d' %(pod, aggr)
                self.addSwitch(aggrThis)
                self.aggrSwitches.append(aggrThis)

                #aggrThis = self.addSwitch("as_"+str(pod)+"_"+str(aggr))
                #aggrThis = self.addSwitch("as_"+str(pod)+"_"+str(aggr), dpid=int2dpid(2, aggr, pod), protocols='OpenFlow14')
                #aggrSwitches.append(aggrThis)
                for x in range((K/2)*aggr, (K/2)*(aggr+1)):
#                    self.addLink(aggrSwitches[aggr+(aggrSwitchNum/podNum*pod)], coreSwitches[x])
                    self.addLink(aggrThis, self.coreSwitches[x])
                    self.addSwitchPort(aggrThis, self.coreSwitches[x])
                    self.addSwitchPort(self.coreSwitches[x], aggrThis)
                    #self.addLink(aggrThis, coreSwitches[x])
        # Edge
            for edge in range(self.edgeSwitchNum/self.podNum):
                edgeThis = self.addSwitch("es_"+str(pod)+"_"+str(edge))
                #edgeThis = self.addSwitch("es_"+str(pod)+"_"+str(edge), dpid=int2dpid(3, edge, pod), protocols='OpenFlow14')
                self.edgeSwitches.append(edgeThis)
                for x in range((self.edgeSwitchNum/self.podNum)*pod, ((self.edgeSwitchNum/self.podNum)*(pod+1))):
                    self.addLink(edgeThis, self.aggrSwitches[x])
                    self.addSwitchPort(edgeThis, self.aggrSwitches[x])
                    self.addSwitchPort(self.aggrSwitches[x], edgeThis)

        # Host

                host_name = "h_"+str(pod)+"_"+str(edge)
                #print host_name
                self.addHost(host_name, ip='10.%d.%d.1/24' %(pod, edge), mac='08:00:00:%02x:%02x:01' %(pod, edge))
                self.hosts_dic.append(host_name)
                self.addLink(edgeThis, host_name)
                self.addSwitchPort(edgeThis, host_name)


        #for sw in edgeSwitches:
            #self.addLink(sw, arpSwitch)

        self.switches_dic = self.coreSwitches + self.aggrSwitches + self.edgeSwitches

    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = {}
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw][node2] = portno



class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : dict<string, dict> // mininet host names and their associated properties
            switches : dict<string, dict> // mininet switch names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, p4info_fpath, topo_file, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False, enable_log=True):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.enable_log = enable_log
        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_fpath)
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe
        self.sw_conn = {}


    def run_exercise(self, mode, K=0):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network(mode, K)
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)
        #CLI(self.net)
        if mode == 1:
            self.SingleSwitchTopoConfig()
        if mode == 3:
            self.LineSwitchTopoConfig()
        if mode == 4:
            pass
        if mode == 5:
            path1 = ['s1', 's2', 's3', 's4', 's5']
            path2 = ['s1', 's2', 's6', 's4', 's5']
            path = ['h_1', 's1', 's2', 's3', 's4', 's5', 'h_5']
            dstAddr_dic = {'h_1': "08:00:00:00:01:01",
                           'h_5': "08:00:00:00:05:05",
                           's1': "08:00:00:00:01:00",
                           's2': "08:00:00:00:02:00",
                           's3': "08:00:00:00:03:00",
                           's4': "08:00:00:00:04:00",
                           's5': "08:00:00:00:05:00"}
            self.TwoPathTopoConfig(path1, path2)
            #self.FatTreeTopoConfig()
        CLI(self.net)
        #self.do_net_cli()
        # stop right after the CLI is exited
        #ShutdownAllSwitchConnections()
        #shut down all the p4runtime connections
        self.shutdown_all_connections()
        self.net.stop()


    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links


    def create_network(self, mode, K):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        if self.enable_log:
            defaultSwitchClass = configureP4Switch(
                                    sw_path=self.bmv2_exe,
                                    json_path=self.switch_json,
                                    log_console=True,
                                    pcap_dump=self.pcap_dir)
        else:
            defaultSwitchClass = configureP4Switch(sw_path=self.bmv2_exe, json_path=self.switch_json)

        if mode == 1:
            print "set up single-switch topology"
            host_num = 3
            self.topo = SingleSwitchTopo(host_num, log_dir=self.log_dir)

        if mode == 2:
            print "set up pod topology"
            self.topo = ExerciseTopo(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe, self.pcap_dir)

        if mode == 3:
            print "set up line topology"
            sw_num = 3
            self.topo = LineSwitchTopo(sw_num)

        if mode == 4:
            print "set up fat tree topology with K=%d" %K
            self.topo = FatTree(K)

        if mode == 5:
            print "set up two-path topology"
            path1 = ['h_1', 's1', 's2', 's3', 's4', 's5', 'h_5']
            path2 = ['h_1', 's1', 's2', 's6', 's4', 's5', 'h_5']
            self.topo = TwoPathTopo(self.log_dir, path1, path2)
            print self.topo.switches_dic


        #print type(self.topo)
        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = defaultSwitchClass,
                      controller = None)


    def shutdown_all_connections(self):
        for sw_name in self.sw_conn:
            p4runtime_lib.simple_controller.shutdown_connection(self.sw_conn[sw_name])



    def program_switch_p4runtime(self, sw_name):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        self.logger('Configuring switch %s using P4Runtime' % sw_name)
        if self.enable_log:
            print "Switch %s log enabled" %sw_name
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, sw_name)
            self.sw_conn[sw_name] = p4runtime_lib.simple_controller.configure_switch(sw_name=sw_name, addr='127.0.0.1:%d' % grpc_port,
                                                                                device_id=device_id,
                                                                                p4info_helper=self.p4info_helper,
                                                                                bmv2_json_fpath=self.switch_json,
                                                                                proto_dump_fpath=outfile)
        else:
            self.sw_conn[sw_name] = p4runtime_lib.simple_controller.configure_switch(sw_name=sw_name, addr='127.0.0.1:%d' % grpc_port,
                                                                                  device_id=device_id,
                                                                                  p4info_helper=self.p4info_helper,
                                                                                  bmv2_json_fpath=self.switch_json)



    def read_switch_rules(self, sw_name):
        p4runtime_lib.simple_controller.readTableEntry(
            sw=self.sw_conn[sw_name],
            p4info_helper=self.p4info_helper)


    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, sw_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=fout)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name in self.topo.switches_dic:
            self.program_switch_p4runtime(sw_name)

    def program_hosts(self):
        """ Execute commands "route add default gw 10.0.1.10 dev eth0",
            "arp -i eth0 -s 10.0.1.10 08:00:00:00:01:00" on every host
        """

        for host_name in self.topo.hosts_dic:
            print "program host %s" %host_name
            h = self.net.get(host_name)
            if len(host_name.split('_')) == 2:
                idx = int(host_name[2:])
                #print idx
                cmd = "route add default gw 10.0.%d.250 dev eth0" %idx
                #print cmd
                h.cmd(cmd)
                cmd = "arp -i eth0 -s 10.0.%d.250 08:00:00:00:%02x:00" %(idx, idx)
                #print cmd
                h.cmd(cmd)

            if len(host_name.split('_')) == 3:
                idx1 = int(host_name.split('_')[1])
                idx2 = int(host_name.split('_')[2])
                cmd = "route add default gw 10.%d.%d.250 dev eth0" %(idx1, idx2)
                #print cmd
                h.cmd(cmd)
                cmd = "arp -i eth0 -s 10.%d.%d.250 08:00:00:%02x:%02x:00" %(idx1, idx2, idx1, idx2)
                #print cmd
                h.cmd(cmd)



    def SingleSwitchTopoConfig(self):

        sw_name = 's1'

        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ('10.0.2.0', '255.255.255.0'),
                "hdr.ipv4.srcAddr": ('10.0.1.0', '255.255.255.0')
                #make sure value & mask == value
            },
            priority=1,
            # priority must be larger than 0 for ternary table entry
            # priority always equal to 0 for exact and lpm table entry
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": '08:00:00:00:01:01',
                "port": 1,
                "rtmp": 2,
                "ttmp": 2,
                "flowid": 1
            })



        self.sw_conn[sw_name].WriteTableEntry(table_entry)

        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ('10.0.1.0', '255.255.255.0'),
                "hdr.ipv4.srcAddr": ('10.0.2.0', '255.255.255.0')
            },
            priority=1,
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": '08:00:00:00:02:02',
                "port": 2,
                "rtmp": 2,
                "ttmp": 2,
                "flowid": 2
            })

        self.sw_conn[sw_name].WriteTableEntry(table_entry)

        self.read_switch_rules(sw_name)

        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ('10.0.1.0', '255.255.255.0'),
                "hdr.ipv4.srcAddr": ('10.0.2.0', '255.255.255.0')
                #make sure value & mask == value
            },
            priority=1,
            # priority must be larger than 0 for ternary table entry
            # priority always equal to 0 for exact and lpm table entry
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": '08:00:00:00:02:02',
                "port": 2,
                "rtmp": 2,
                "ttmp": 2,
                "flowid": 2
            })

        self.sw_conn[sw_name].WriteTableEntry(table_entry=table_entry, update_flag=1)

        self.read_switch_rules(sw_name)

        # table_entry = self.p4info_helper.buildTableEntry(
        #     table_name="MyIngress.ipv4_lpm",
        #     match_fields={
        #         "hdr.ipv4.dstAddr": ('10.0.3.0', '255.255.255.0')
        #     },
        #     priority=1,
        #     action_name="MyIngress._resubmit")
        #
        # sw.WriteTableEntry(table_entry)

        #sw.shutdown()

        sleep(1)


    def TwoPathTopoConfig(self, path1, path2):
        dstAddr_dic = {'h_1': "08:00:00:00:01:01",
                       'h_5': "08:00:00:00:05:05",
                       's1': "08:00:00:00:01:00",
                       's2': "08:00:00:00:02:00",
                       's3': "08:00:00:00:03:00",
                       's4': "08:00:00:00:04:00",
                       's5': "08:00:00:00:05:00",
                       's6': "08:00:00:00:06:00"}

        state = net()
        old_path = ['h_1', 's1', 's2', 's3', 's4', 's5', 'h_5']
        old_path_reverse = ['h_1', 's1', 's2', 's3', 's4', 's5', 'h_5']
        old_path_reverse.reverse()
        new_path = ['h_1', 's1', 's2', 's6', 's4', 's5', 'h_5']
        new_path_reverse = ['h_1', 's1', 's2', 's6', 's4', 's5', 'h_5']
        new_path_reverse.reverse()
        out_port_old = {'s1': 1, 's2': 2, 's3': 2, 's4': 2, 's5': 2}
        out_port_new = {'s1': 1, 's2': 3, 's6': 2, 's4': 2, 's5': 2}
        in_port_old = {'s1': 2, 's2': 1, 's3': 1, 's4': 1, 's5': 1}
        in_port_new = {'s1': 2, 's2': 1, 's6': 1, 's4': 3, 's5': 1}
        prt = 3
        clk = 7
        for i in set(old_path[1:-1] + new_path[1:-1]):
            state.add_table(i, 0)
        match = {}
        match["ipv4_src"] = "10.0.1.0"
        match["mask_src"] = "255.255.255.0"
        match["ipv4_dst"] = "10.0.5.0"
        match["mask_dst"] = "255.255.255.0"
        flow_id = 2

        cwdpath = os.getcwd()

        match_reverse = {}
        match_reverse["ipv4_src"] = "10.0.5.0"
        match_reverse["mask_src"] = "255.255.255.0"
        match_reverse["ipv4_dst"] = "10.0.1.0"
        match_reverse["mask_dst"] = "255.255.255.0"
        flow_id_reverse = 1

        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ('10.0.0.0', '255.0.0.0'),
                "hdr.ipv4.srcAddr": ('10.0.0.0', '255.0.0.0')
                #make sure value & mask == value
            },
            priority=1,
            # priority must be larger than 0 for ternary table entry
            # priority always equal to 0 for exact and lpm table entry
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": '08:00:00:00:00:00',
                "port": 0,
                "rtmp": 1,
                "ttmp": 1,
                "flowid": 0
            })

        for sw_name in set(old_path[1:-1] + new_path[1:-1]):
            self.sw_conn[sw_name].WriteTableEntry(table_entry=table_entry)

        p4runtime_lib.simple_controller.path_deploy(self.p4info_helper, [], old_path, match, state, prt, {}, out_port_old, {}, dstAddr_dic, clk, self.net, self.sw_conn, flow_id)
        p4runtime_lib.simple_controller.path_deploy(self.p4info_helper, [], old_path_reverse, match_reverse, state, prt, {}, in_port_old, {}, dstAddr_dic, clk, self.net, self.sw_conn, flow_id_reverse)

        for sw_name in self.topo.switches_dic:
            self.read_switch_rules(sw_name)
        CLI(self.net)

        sleep(4)

        h_src = self.net.get('h_1')
        h_dst = self.net.get('h_5')

        sendpath = cwdpath + '/send_cnt.py'
        recpath = cwdpath + '/receive_cnt.py'

        #delay = 1.0 / pkt_rate - 0.001
        h_dst.cmd('python', recpath, '&')
        sleep(1)
        h_src.cmd('python', sendpath, "-s 10.0.1.1 -d 10.0.5.5 -n 500 -m haha -t 2", '&')

        clk += 1
        p4runtime_lib.simple_controller.path_deploy(self.p4info_helper, old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dstAddr_dic, clk, self.net, self.sw_conn, flow_id)
        p4runtime_lib.simple_controller.path_deploy(self.p4info_helper, old_path_reverse, new_path_reverse, match_reverse, state, prt, in_port_old, in_port_new, out_port_old, dstAddr_dic, clk, self.net, self.sw_conn, flow_id)
        #CLI(self.net)
        sleep(10)
        #print out

        ping_ret_o = h_dst.cmd('echo')
        #print h_src.cmd('echo')
        #print ping_ret_o
        #recv_num = ping_ret_o.strip().split('\n')[1]
        print ping_ret_o




    def LineSwitchTopoConfig(self):
        sw_num = len(self.topo.switches_dic)
        for i in range(1, sw_num+1):
            sw_name = "s%d" %i
            sw_obj = self.net.get(sw_name)
            grpc_port = sw_obj.grpc_port
            device_id = sw_obj.device_id
            if self.enable_log:
                sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name,
                                                            address='localhost:%d' %grpc_port,
                                                            device_id=device_id,
                                                            proto_dump_file='logs/%s-p4runtime-requests.txt' %sw_name)
            else:
                sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=sw_name,
                                                            address='localhost:%d' %grpc_port,
                                                            device_id=device_id)

            sw.MasterArbitrationUpdate()

            if i == 1:
                dstAddr1 = '08:00:00:00:01:01'
                dstAddr2 = '08:00:00:00:%02x:00' %(i+1)
                port1 = self.topo.sw_port_mapping['s%d' %i]["h1"]
                port2 = self.topo.sw_port_mapping['s%d' %i]['s%d' %(i+1)]
            elif i == sw_num:
                dstAddr1 = '08:00:00:00:%02x:00' %(i-1)
                dstAddr2 = '08:00:00:00:02:02'
                port1 = self.topo.sw_port_mapping['s%d' %i]['s%d' %(i-1)]
                port2 = self.topo.sw_port_mapping['s%d' %i]["h2"]
            else:
                dstAddr1 = '08:00:00:00:%02x:00' %(i-1)
                dstAddr2 = '08:00:00:00:%02x:00' %(i+1)
                port1 = self.topo.sw_port_mapping['s%d' %i]['s%d' %(i-1)]
                port2 = self.topo.sw_port_mapping['s%d' %i]['s%d' %(i+1)]


            #print dstAddr1, port1, dstAddr2, port2

            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": ('10.0.1.0', '255.255.255.0')
                    #make sure value & mask == value
                },
                priority=1,
                # priority must be larger than 0 for ternary table entry
                # priority always equal to 0 for exact and lpm table entry
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": dstAddr1,
                    "port": port1,
                    "rtmp": 2,
                    "ttmp": 2
                })

            sw.WriteTableEntry(table_entry)

            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": ('10.0.2.0', '255.255.255.0')
                    #make sure value & mask == value
                },
                priority=1,
                # priority must be larger than 0 for ternary table entry
                # priority always equal to 0 for exact and lpm table entry
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": dstAddr2,
                    "port": port2,
                    "rtmp": 2,
                    "ttmp": 2
                })

            sw.WriteTableEntry(table_entry)






            sw.shutdown()

        sleep(1)


    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False, default='./build/basic.json')
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch_grpc')
    parser.add_argument('-e', '--enable-log', help='enable log',
                                action='store_true', required=False, default=True)
    return parser.parse_args()


if __name__ == '__main__':
    # from mininet.log import setLogLevel
    # setLogLevel("info")

    args = get_args()
    print args
    p4info_file_path = os.getcwd() + '/build/basic.p4.p4info.txt'
    exercise = ExerciseRunner(p4info_file_path, args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet, args.enable_log)

    mode = 1
    K = 1
    exercise.run_exercise(mode, K)
