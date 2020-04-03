from switch_state import rule, table, net
import copy

SBPRT = 50

def state_update(rule_set, state, table_id=0, cu=0):
    for i in rule_set:
        tb = state.get_table(i, table_id)
        for r in rule_set[i]['del']:
            if cu:
                tb.del_rule_tmp(r.get_match(), r.get_prt(), r.get_rtmp())
            else:
                tb.del_rule(r.get_match(), r.get_prt())
        for r in rule_set[i]['add']:
            if cu:
                tb.add_rule_tmp(r.get_match(), r.get_action(), r.get_dst_mac(), r.get_rtmp(), r.get_ttmp(), r.get_flow_id(), r.get_prt())
            else:
                tb.add_rule(r.get_match(), r.get_action(), r.get_dst_mac(), r.get_rtmp(), r.get_ttmp(), r.get_flow_id(), r.get_prt())
    return state


def setTMP(old_path, new_path, match, state, rule_set, clk, in_port, dst_mac, flow_id, table_id=0):
    # set rule timestamp
    for i in rule_set:
        for r in rule_set[i]['add']:
            r.set_rtmp(clk)
    state = state_update(rule_set, state, table_id)

    # add send_back rules
    for i in range(1, len(old_path)-1):
        if old_path[i] not in new_path:
            if old_path[i] not in rule_set:
                rule_set[old_path[i]] = {'add': [], 'del': []}
            rule_set[old_path[i]]['add'].append(rule(old_path[i], match, in_port[old_path[i]], dst_mac[old_path[i-1]], clk, clk, flow_id, table_id, SBPRT))
    # state.print_state()
    for i in range(1, len(new_path)-2):
        if new_path[i] in rule_set:
            for r in rule_set[new_path[i]]['add']:
                if r.get_ttmp() == 0:
                    tb_next = state.get_table(new_path[i+1], table_id)
                    r_next = tb_next.get_rule(match)
                    #r_next.print_rule()
                    r.set_ttmp(r_next.get_rtmp())
    state = state_update(rule_set, state, table_id)

    return rule_set


def setTMP_wp(old_path, new_path, match, state, rule_set, clk, in_port, table_id=0):
    # set rule timestamp
    for i in rule_set:
        for r in rule_set[i]['add']:
            r.set_rtmp(clk)
    state = state_update(rule_set, state, table_id)

    # state.print_state()
    for i in range(len(new_path)-1):
        if new_path[i] in rule_set:
            for r in rule_set[new_path[i]]['add']:
                if r.get_ttmp() == 0:
                    tb_next = state.get_table(new_path[i+1], table_id)
                    r_next = tb_next.get_rule(match)
                    #r_next.print_rule()
                    r.set_ttmp(r_next.get_rtmp())
    state = state_update(rule_set, state, table_id)

    return rule_set



def rule_construct_normal(old_path, new_path, match, state, prt, out_port, dst_mac, flow_id=0, table_id=0):
    # a simplified version of one-big-switch
    rule_set = {}
    #match = {}
    #match['ipv4_dst'] = flow['ipv4_dst']
    #match['ipv4_src'] = flow['ipv4_src']

    if old_path:
        for i in range(1, len(old_path)-2):
            if (old_path[i] in new_path) and (old_path[i+1] not in new_path):
                rule_set[old_path[i]] = {'add': [], 'del': []}
                rext = state.get_table(old_path[i], table_id).get_rule(match)
                if rext.get_prt() == prt:
                    rule_set[old_path[i]]['del'].append(rule(old_path[i], rext.get_match(), rext.get_action(), rext.get_dst_mac(), rext.get_rtmp(), rext.get_ttmp(), rext.get_flow_id(), table_id, rext.get_prt()))
                rule_set[old_path[i]]['add'].append(rule(old_path[i], match, out_port[old_path[i]], dst_mac[new_path[i+1]], 0, 0, flow_id, table_id, prt))


    for i in (set(old_path[1:-1]) - set(new_path[1:-1])):
        if i not in rule_set:
            rule_set[i] = {'add': [], 'del': []}
        rext = state.get_table(i, table_id).get_rule(match)
        if rext.get_prt() == prt:
            rule_set[i]['del'].append(rule(i, rext.get_match(), rext.get_action(), rext.get_dst_mac(), rext.get_rtmp(), rext.get_ttmp(), rext.get_flow_id(), table_id, rext.get_prt()))


    for i in range(1, len(new_path)-1):
        if new_path[i] not in old_path:
            rule_set[new_path[i]] = {'add': [], 'del': []}
            rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port[new_path[i]], dst_mac[new_path[i+1]], 0, 0, flow_id, table_id, prt))

    return rule_set


def rule_construct_scc(old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dst_mac, clk, flow_id=0, table_id=0):
    rule_set = rule_construct_normal(old_path, new_path, match, state, prt, out_port_new, dst_mac, flow_id, table_id)
    rule_set = setTMP(old_path, new_path, match, state, rule_set, clk, in_port_old, dst_mac, flow_id)
    return [rule_set]


def rule_construct_scc_wp(old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dst_mac, clk, flow_id=0, table_id=0):
    rule_deploy = []
    rule_set = rule_construct_normal(old_path, new_path, match, state, prt, out_port_new, dst_mac, flow_id, table_id)
    rule_set = setTMP_wp(old_path, new_path, match, state, rule_set, clk, in_port_old)
    if not old_path:
        rule_deploy.append(rule_set)
        return rule_deploy
    for i in range(len(new_path)-1):
        if (new_path[i] in old_path) and (new_path[i+1] not in old_path):
            inter_first = new_path[i]
            break
    rule_deploy.append({inter_first:rule_set[inter_first]})
    del rule_set[inter_first]
    rule_deploy.append(rule_set)
    return rule_deploy


def rule_construct(old_path, new_path, match, state, prt, out_port_old, out_port_new, clk, table_id=0):
    rule_set = {}

    if old_path:
        rule_set = {}
        #intersect_set = []
        for i in range(len(new_path)-1):
            #if (old_path[i] in new_path) and (old_path[i+1] not in new_path):
            if (new_path[i] in old_path) and (new_path[i+1] not in old_path):
                inter_first = i
                break
                #intersect_set.append(i)

        for i in range(len(new_path)-1):
            if (new_path[len(new_path)-i-1] in old_path) and (new_path[len(new_path)-i-2] not in old_path):
                inter_last = len(new_path)-i-1
                break

        print inter_first
        print inter_last

        for j in range(inter_first, inter_last):
            i = new_path[j]
            rule_set[i] = {'add': [], 'del': []}
            if i in old_path:
                rule_set[i]['del'].append(rule(i, match, out_port_old[i], clk-1, clk-1, table_id, prt))
            rule_set[i]['add'].append(rule(i, match, out_port_new[i], clk, 0, table_id, prt))

        for i in (set(old_path) - set(new_path)):
            if i not in rule_set:
                rule_set[i] = {'add': [], 'del': []}
            rule_set[i]['del'].append(rule(i, match, out_port_old[i], clk-1, clk-1, table_id, prt))

    else:

        for i in set(new_path):
            rule_set[i] = {'add': [], 'del': []}
            if i == new_path[0]:
                rule_set[i]['add'].append(rule(i, match, out_port_new[i], 0, clk, table_id, prt))
            else:
                rule_set[i]['add'].append(rule(i, match, out_port_new[i], clk, 0, table_id, prt))

    return rule_set


def sb_rule_clean(old_path, new_path, match, clk, in_port, table_id=0):
    sb_set = {}
    for i in (set(old_path) - set(new_path)):
        if i not in sb_set:
            sb_set[i] = {'add': [], 'del': []}
        sb_set[i]['del'].append(rule(i, match, in_port[i], clk, clk, table_id, SBPRT))
    return sb_set


def rule_construct_cu(old_path, new_path, match, state, prt, out_port_old, out_port_new, clk, table_id=0):
    rule_deploy = []

    if not old_path:
        rule_set = {}
        for i in range(len(new_path)):
            rule_set[new_path[i]] = {'add': [], 'del': []}
            if i == len(new_path)-1:
                rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port_new[new_path[i]], clk, 0, table_id, prt))
            elif i == 0:
                rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port_new[new_path[i]], 0, clk, table_id, prt))
            else:
                rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port_new[new_path[i]], clk, clk, table_id, prt))
        rule_deploy.append(rule_set)
    else:
        rule_set = {}
        for i in range(1, len(new_path)):
            rule_set[new_path[i]] = {'add': [], 'del': []}
            if i == len(new_path)-1:
                rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port_new[new_path[i]], clk, 0, table_id, prt))
            else:
                rule_set[new_path[i]]['add'].append(rule(new_path[i], match, out_port_new[new_path[i]], clk, clk, table_id, prt))
        rule_deploy.append(rule_set)

        first_rule = {}
        first_rule[new_path[0]] = {}
        first_rule[new_path[0]]['add'] = [rule(new_path[0], match, out_port_new[new_path[0]], 0, clk,  table_id, prt)]
        first_rule[new_path[0]]['del'] = [rule(new_path[0], match, out_port_old[new_path[0]], 0, clk-1, table_id, prt)]
        rule_deploy.append(first_rule)

        del_set = {}
        for i in range(1, len(old_path)):
            del_set[old_path[i]] = {'add': [], 'del': []}
            if i == len(old_path)-1:
                del_set[old_path[i]]['del'].append(rule(old_path[i], match, out_port_old[old_path[i]], clk-1, 0, table_id, prt))
            else:
                del_set[old_path[i]]['del'].append(rule(old_path[i], match, out_port_old[old_path[i]], clk-1, clk-1, table_id, prt))
        rule_deploy.append(del_set)

    for rule_set in rule_deploy:
        state = state_update(rule_set, state, table_id, 1)
        #state.print_state()
    return rule_deploy



if __name__ == '__main__':
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
    #rule_set = rule_construct_normal([], old_path, match, state, prt, out_port_old)
    #rule_deploy = rule_construct_cu([], old_path, match, state, prt, {}, out_port_old, clk)
    rule_deploy = rule_construct_scc([], old_path, match, state, prt, {}, out_port_old, {}, dstAddr_dic, clk, flow_id)
    for t in range(len(rule_deploy)):
        rule_set = rule_deploy[t]
        print "new step %d" %t
    #if True:
        print "rules to be added:"
        for s in rule_set:
            for r in rule_set[s]['add']:
                r.print_rule()

        print "rules to be deleted:"
        for s in rule_set:
            for r in rule_set[s]['del']:
                r.print_rule()

    print "after update"
    #state = state_update(rule_set, state)
    print "new state"
    state.print_state()
    clk += 1
    #rule_set = rule_construct_normal(old_path, new_path, match, state, prt, out_port_new)
    #rule_deploy = rule_construct_cu(old_path, new_path, match, state, prt, out_port_old, out_port_new, clk)
    rule_deploy = rule_construct_scc(old_path, new_path, match, state, prt, out_port_old, out_port_new, in_port_old, dstAddr_dic, clk, flow_id)
    for t in range(len(rule_deploy)):
        rule_set = rule_deploy[t]
        print "new step %d" %t
    #if True:
        print "rules to be added:"
        for s in rule_set:
            for r in rule_set[s]['add']:
                r.print_rule()

        print "rules to be deleted:"
        for s in rule_set:
            for r in rule_set[s]['del']:
                r.print_rule()
    print "new state"
    state.print_state()
