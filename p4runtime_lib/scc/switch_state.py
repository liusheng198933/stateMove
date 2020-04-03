import copy

class rule:
    def __init__(self, dpid, match, action, dst_mac, rtmp=0, ttmp=0, flow_id=0, table_id=0, priority=1):
        # self.next_sid is the identifier of the switch
        # match is a dictionary, including 'ipv4_dst', 'ipv4_src', 'mask_dst', 'mask_src'.
        self.dpid = dpid
        self.match = match
        self.action = action
        # action = 0: drop;  action = -1: send back
        self.priority = priority
        self.table_id = table_id
        self.dst_mac = dst_mac
        self.rtmp = rtmp
        self.ttmp = ttmp
        self.flow_id = flow_id


    def print_rule(self):
        printstr = []
        if type(self.rtmp) == int:
            printstr.append("rule dpid: %s, prt: %d, action: %d, dst_mac: %s, rtmp: %d, ttmp: %d, flow_id: %d, table_id: %d\n" % (str(self.dpid), self.priority, self.action, self.dst_mac, self.rtmp, self.ttmp, self.flow_id, self.table_id))
        else:
            printstr.append("rule dpid: %s, prt: %d, action: %d, dst_mac: %s, rtmp_min: %d, rtmp_max: %d, ttmp: %d, flow_id: %d, table_id: %d\n" % (str(self.dpid), self.priority, self.action, self.dst_mac, self.rtmp[0], self.rtmp[1], self.ttmp, self.flow_id, self.table_id))
        printstr.append("match: %s" % str(self.match))
        print "".join(printstr)


    def get_rule(self):
        return {'dpid': self.dpid, 'match': self.match, 'action': self.action, 'priority':self.priority, 'rtmp': self.rtmp, 'ttmp': self.ttmp, 'table_id': self.table_id}

    def if_match(self, flow):
        src = flow['ipv4_src'].split('.')
        src_m = self.match['ipv4_src'].split('.')
        src_mask = self.match['mask_src'].split('.')
        for i in range(len(src)):
            #print int(src[i]) & int(src_mask[i])
            #print int(src_m[i]) & int(src_mask[i])
            if int(src[i]) & int(src_mask[i]) != int(src_m[i]) & int(src_mask[i]):
                return False

        dst = flow['ipv4_dst'].split('.')
        dst_m = self.match['ipv4_dst'].split('.')
        dst_mask = self.match['mask_dst'].split('.')
        for i in range(len(dst)):
            #print int(dst[i]) & int(dst_mask[i])
            #print int(dst_m[i]) & int(dst_mask[i])
            if int(dst[i]) & int(dst_mask[i]) != int(dst_m[i]) & int(dst_mask[i]):
                return False
        return True


    def if_equal(self, match_cmp, prt_cmp):
        return prt_cmp == self.priority and self.match == match_cmp

    def if_equal_tmp(self, match_cmp, prt_cmp, rtmp):
        return prt_cmp == self.priority and self.match == match_cmp and self.rtmp == rtmp


    def get_dpid(self):
        return self.dpid

    def get_table_id(self):
        return self.table_id

    def get_match(self):
        return self.match

    def get_rtmp(self):
        return self.rtmp

    def get_flow_id(self):
        return self.flow_id

    def get_dst_mac(self):
        return self.dst_mac

    def get_ttmp(self):
        return self.ttmp

    def get_prt(self):
        return self.priority

    def get_action(self):
        return self.action

    def set_dpid(self, value):
        self.dpid = value

    def set_prt(self, value):
        self.priority = value

    def set_rtmp(self, value):
        self.rtmp = value

    def set_ttmp(self, value):
        self.ttmp = value

    def set_match(self, value):
        self.match = value

    def set_flow_id(self, value):
        self.flow_id = value

    def set_dst_mac(self, value):
        self.dst_mac = value

    def set_table_id(self, value):
        self.table_id = value

    def set_action(self, value):
        self.action = value


class table:
    # create an image of the switch flow table
    def __init__(self, dpid, table_id):
        self.tb = {}
        self.dpid = dpid
        self.table_id = table_id

    def clear(self):
        self.tb.clear()

    def add_rule(self, match, action, dst_mac, rtmp=0, ttmp=0, flow_id=0, priority=1):
        tb_pr = self.tb.setdefault(priority, set())
        for r in tb_pr:
            if r.if_match(match):
                tb_pr.remove(r)
                break
        tb_pr.add(rule(self.dpid, match, action, dst_mac, rtmp, ttmp, flow_id, self.table_id, priority))
        return True

    def add_rule_tmp(self, match, action, dst_mac, rtmp, ttmp=0, flow_id=0, priority=1):
        tb_pr = self.tb.setdefault(priority, set())
        for r in tb_pr:
            if r.if_match(match) and r.rtmp == rtmp:
                tb_pr.remove(r)
                break
        tb_pr.add(rule(self.dpid, match, action, dst_mac, rtmp, ttmp, flow_id, self.table_id, priority))
        return True

    def del_rule(self, match, priority):
        for r in self.tb[priority]:
            if r.if_equal(match, priority):
                self.tb[priority].remove(r)
                return True
        return False

    def del_rule_tmp(self, match, priority, rtmp):
        for r in self.tb[priority]:
            if r.if_equal_tmp(match, priority, rtmp):
                self.tb[priority].remove(r)
                return True
        return False

    def get_rule(self, flow):
        #rprt = 0
        prt_list = self.tb.keys()
        prt_list.sort()
        for i in range(len(prt_list)-1, -1, -1):
            for r in self.tb[prt_list[i]]:
                if r.if_match(flow):
                    return r
        return None


    def get_all_rules(self):
        return self.tb

    def get_dpid(self):
        return self.dpid

    def get_rule_num(self):
        num = 0
        for i in self.tb:
            num += len(self.tb[i])
        return num

    def set_table(self, flowTable):
        self.clear()
        for i in flowTable:
            for r in flowTable[i]:
                self.add_rule(r.get_match(), r.get_action(), r.get_dst_mac(), r.get_rtmp(), r.get_ttmp(), r.get_flow_id(), r.get_table_id(), r.get_prt())

    def print_table(self):
        for i in self.tb:
            for r in self.tb[i]:
                r.print_rule()

class net():
    def __init__(self):
        self.state = {}

    def add_switch(self, dpid):
        self.state[dpid] = {}

    def del_switch(self, dpid):
        del self.state[dpid]

    def add_table(self, dpid, table_id):
        if dpid not in self.state:
            self.add_switch(dpid)
        self.state[dpid][table_id] = table(dpid, table_id)

    def get_state(self):
        return self.state

    def get_switch(self, dpid):
        return self.state[dpid]

    def get_table(self, dpid, table_id):
        return self.state[dpid][table_id]

    def copy_state(self, state_copy):
        self.state = copy.deepcopy(state_copy.get_state())

    def print_state(self):
        for i in self.state:
            for j in self.state[i]:
                print "switch %s, table id: %s" %(str(i), str(j))
                self.state[i][j].print_table()


if __name__ == '__main__':
    #filepath = "/home/shengliu/Workspace/mininet/haha/cmd_test.sh"

    #switch_query(filepath, 3)
    #process = subprocess.Popen('%s' %filepath, stdout=subprocess.PIPE)
    #output, error = process.communicate()

    #rule_list = parse_query(output)
    #for r in rule_list:
    #    r.print_rule()

    n = net()
    n.add_table('s1',0)
    n.add_table('s2',0)
    n.add_table('s3',0)

    match = {}
    match["ipv4_src"] = "10.0.1.0"
    match["mask_src"] = "255.255.255.0"
    match["ipv4_dst"] = "10.0.2.0"
    match["mask_dst"] = "255.255.255.0"

    flow = {}
    flow["ipv4_src"] = "10.0.1.1"
    flow["ipv4_dst"] = "10.0.2.252"

    n.get_table('s1', 0).add_rule(match, 2, "08:00:00:00:02:02", 1, 2, 1, 1)
    n.get_table('s1', 0).add_rule(match, 3, "08:00:00:00:02:02", 1, 3, 1, 2)
    n.get_table('s2', 0).add_rule(match, 3, "08:00:00:00:02:02", 2, 3, 1, 1)

    n.get_table('s1', 0).print_table()
    n.get_table('s1', 0).get_rule(flow).print_rule()
    #print n.get_table(1, 0).get_rule(flow).get_action()
    #print n.get_table(3, 0).get_rule(flow).get_action()
    #print n.get_table(1, 0).get_rule(flow).get_rtmp()
    #print n.get_table(1, 0).get_rule(flow).get_ttmp()
    #print n.get_table(2, 0).get_rule(flow).get_action()
    #print n.get_table(2, 0).get_rule(flow).get_rtmp()
    #print n.get_table(2, 0).get_rule(flow).get_ttmp()
