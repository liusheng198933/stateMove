from util import *


def path_read(filepath, K):
    # return list of old path, new path and its corresponding flow (ip_src and ip_dst)
    #flow_set = set()
    with open(filepath, 'r') as f:
        content = f.readlines()
        rmchars = '\"\'<>(),'
        old_path_list = []
        new_path_list = []
        flow_list = []
        ct = 0
        for x in content:
            old_path_dic = {}
            old_path_dic['path'] = []
            old_path_dic['out_port'] = []
            old_path_dic['in_port'] = []
            new_path_dic = {}
            new_path_dic['path'] = []
            new_path_dic['out_port'] = []
            new_path_dic['in_port'] = []
            flow = {}
            ret = x.strip().split()[1:]
            if len(ret) != 30 and len(ret) != 18:
                print ret
                print len(ret)
                print x

            for i in range(len(ret)):
                t = ret[i].strip(rmchars)
                if i < len(ret)/2:
                    if i%3 == 0:
                        old_path_dic['path'].append(switch_id_parse(t, K))
                    if i%3 == 1:
                        old_path_dic['in_port'].append(int(t))
                    if i%3 == 2:
                        old_path_dic['out_port'].append(int(t))
                if i >= len(ret)/2:
                    if i%3 == 0:
                        new_path_dic['path'].append(switch_id_parse(t, K))
                    if i%3 == 1:
                        new_path_dic['in_port'].append(int(t))
                    if i%3 == 2:
                        new_path_dic['out_port'].append(int(t))
            old_path_list.append(old_path_dic)
            new_path_list.append(new_path_dic)
            flow['ipv4_src'] = get_host_IP(old_path_dic['in_port'][0], old_path_dic['path'][0], K)
            flow['ipv4_dst'] = get_host_IP(old_path_dic['out_port'][len(old_path_dic['out_port'])-1], old_path_dic['path'][len(old_path_dic['path'])-1], K)
            #flow_set.add(tuple(old_path_dic['path']))
            #flow_set.add(tuple(new_path_dic['path']))
            #print tuple(old_path_dic['path'])
            #ct += 1
            #if ct == 5000:
            #    print len(flow_set)
        return {'old_path': old_path_list, 'new_path': new_path_list, 'flow': flow_list}


def path_read_time(filepath, K):
    # return list of old path, new path and its corresponding flow (ip_src and ip_dst)
    with open(filepath, 'r') as f:
        content = f.readlines()
        rmchars = '\"\'<>(),'
        old_path_list = []
        new_path_list = []
        flow_list = []
        time_list = []
        for x in content:
            old_path_dic = {}
            old_path_dic['path'] = []
            old_path_dic['out_port'] = []
            old_path_dic['in_port'] = []
            new_path_dic = {}
            new_path_dic['path'] = []
            new_path_dic['out_port'] = []
            new_path_dic['in_port'] = []
            flow = {}
            ret = x.strip().split()
            time_list.append(float(ret[0]))
            ret = ret[1:]
            if len(ret) != 30 and len(ret) != 18:
                print ret
                print len(ret)
                print x

            for i in range(len(ret)):
                t = ret[i].strip(rmchars)
                if i < len(ret)/2:
                    if i%3 == 0:
                        old_path_dic['path'].append(switch_id_parse(t, K))
                    if i%3 == 1:
                        old_path_dic['in_port'].append(int(t))
                    if i%3 == 2:
                        old_path_dic['out_port'].append(int(t))
                if i >= len(ret)/2:
                    if i%3 == 0:
                        new_path_dic['path'].append(switch_id_parse(t, K))
                    if i%3 == 1:
                        new_path_dic['in_port'].append(int(t))
                    if i%3 == 2:
                        new_path_dic['out_port'].append(int(t))
            old_path_list.append(old_path_dic)
            new_path_list.append(new_path_dic)
            flow['ipv4_src'] = get_host_IP(old_path_dic['in_port'][0], old_path_dic['path'][0], K)
            flow['ipv4_dst'] = get_host_IP(old_path_dic['out_port'][len(old_path_dic['out_port'])-1], old_path_dic['path'][len(old_path_dic['path'])-1], K)
            flow_list.append(flow)

        return {'old_path': old_path_list, 'new_path': new_path_list, 'flow': flow_list, 'time': time_list}



def process_time_coco(filepath):
    # return list of old path, new path and its corresponding flow (ip_src and ip_dst)
    with open(filepath, 'r') as f:
        content = f.readlines()
        update_time_list = []
        persist_time_list = []
        for i in range(len(content)):
            if content[i].startswith('begin time'):
                ret = content[i:i+40]
                sec = float(ret[0].split()[2])
                micro = float(ret[0].split()[3])
                basic_time = sec + micro/1000000
                rule_num = 0
                install_time = {}
                #install_time['25'] = basic_time
                persist_time = {}
                for j in range(len(ret)):
                    if 'rules commit' in ret[j]:
                        sec = float(ret[j].split()[5])
                        micro = float(ret[j].split()[6])
                        if ret[j].split()[1] in ['21', '23', '24', '25'] and rule_num <= 4:
                            install_time[ret[j].split()[1]] = sec + micro/1000000
                        if ret[j].split()[1] in ['21', '25', '23', '24'] and rule_num > 8:
                            persist_time[ret[j].split()[1]] = sec + micro/1000000 - install_time[ret[j].split()[1]]
                        if rule_num < 13:
                            rule_num = rule_num + 1
                        else:
                            sec = float(ret[j].split()[5])
                            micro = float(ret[j].split()[6])
                            fin_time = sec + micro/1000000
                #print persist_time
                #print install_time
                #print persist_time
                if rule_num == 13:
                    for j in persist_time.keys():
                        persist_time_list.append(1000 * persist_time[j])
                    update_time_list.append(1000 * (fin_time - basic_time))
        return {'update': update_time_list, 'persist': persist_time_list}


def process_time_cu(filepath):
    # return list of old path, new path and its corresponding flow (ip_src and ip_dst)
    with open(filepath, 'r') as f:
        content = f.readlines()
        update_time_list = []
        persist_time_list = []
        for i in range(len(content)):
            if content[i].startswith('begin time'):
                ret = content[i:i+22]
                sec = float(ret[0].split()[2])
                micro = float(ret[0].split()[3])
                basic_time = sec + micro/1000000
                rule_num = 0
                install_time = {}
                #install_time['25'] = basic_time
                persist_time = {}
                for j in range(len(ret)):
                    if 'rules commit' in ret[j]:
                        sec = float(ret[j].split()[5])
                        micro = float(ret[j].split()[6])
                        if ret[j].split()[1] in ['21', '25', '23', '24']:
                            if ret[j].split()[1] not in install_time:
                                install_time[ret[j].split()[1]] = sec + micro/1000000
                            else:
                                persist_time[ret[j].split()[1]] = sec + micro/1000000 - install_time[ret[j].split()[1]]
                                #persist_time[ret[j].split()[1]] = sec + micro/1000000 - basic_time
                        if rule_num < 9:
                            rule_num = rule_num + 1
                        else:
                            sec = float(ret[j].split()[5])
                            micro = float(ret[j].split()[6])
                            fin_time = sec + micro/1000000
                for j in persist_time.keys():
                    persist_time_list.append(1000 * persist_time[j])
                update_time_list.append(1000 * (fin_time - basic_time))
        return {'update': update_time_list, 'persist': persist_time_list}



def process_time(filepath):
    # return list of old path, new path and its corresponding flow (ip_src and ip_dst)
    with open(filepath, 'r') as f:
        content = f.readlines()
        update_time_list = []
        persist_time_list = []
        for i in range(len(content)):
            if content[i].startswith('begin time'):
                ret = content[i:i+10]
                sec = float(ret[0].split()[2])
                micro = float(ret[0].split()[3])
                basic_time = sec + micro/1000000
                rule_num = 0
                for j in range(len(ret)):
                    if ret[j].startswith('del prt: 100'):
                        sec = float(ret[j].split()[12])
                        micro = float(ret[j].split()[13])
                        del_time = sec + micro/1000000
                    if 'rules commit' in ret[j]:
                        if ret[j].split()[1] == '25':
                            sec = float(ret[j].split()[5])
                            micro = float(ret[j].split()[6])
                            install_time = sec + micro/1000000
                        if rule_num < 2:
                            rule_num = rule_num + 1
                        else:
                            sec = float(ret[j].split()[5])
                            micro = float(ret[j].split()[6])
                            fin_time = sec + micro/1000000
                if rule_num == 2:
                    update_time_list.append(1000 * (max(fin_time, del_time) - basic_time))
                    persist_time_list.append(1000 * (del_time - install_time))
                if del_time - install_time < 0:
                    print content[i:i+10]
        return {'update': update_time_list, 'persist': persist_time_list}



def get_host_IP(port_ID, dpid, K):
    name = grpc2name(K, dpid)
    if len(name.split('_')) < 3:
        return False
    #if dpid[0] != '3':
    #    return False
    podNum = int(name.split('_')[1])
    swNum = int(name.split('_')[2])
    return '10.%d.%d.%d' %(podNum, swNum, port_ID-K/2)


def switch_id_parse(sw_str, K):
    if sw_str.startswith('edge'):
        x = int(sw_str[4:])
        podNum = x/(K/2)
        swNum = x%(K/2)
        return name2grpc(K, "es_%d_%d" %(podNum, swNum))
        #return int2dpid(3, swNum, podNum)
    if sw_str.startswith('aggr'):
        x = int(sw_str[4:])
        podNum = x/(K/2)
        swNum = x%(K/2)
        return name2grpc(K, "as_%d_%d" %(podNum, swNum))
        #return int2dpid(2, swNum, podNum)
    if sw_str.startswith('root'):
        swNum = int(sw_str[4:])
        return name2grpc(K, "cs_%d" %swNum)
        #return int2dpid(1, swNum)




if __name__ == '__main__':

    filepath = '/home/shengliu/Workspace/behavioral-model/targets/simple_switch_grpc/newtest/python/flow_update_8.tsv'
    K = 4
    path_list = path_read(filepath, K)

    # ret = process_time_coco('result.txt')
    # utime = ret['update']
    # ptime = ret['persist']
    # print utime
    # print ptime
    # print len(utime)
    # print len(ptime)
    # print sum(utime)/len(utime)
    # print sum(ptime)/len(ptime)

    """
    fp = open('matu_cu.txt', 'w')
    for item in utime:
        fp.write("%f " % item)
    fp.close()

    fp = open('matp_cu.txt', 'w')
    for item in ptime:
        fp.write("%f " % item)
    fp.close()
    """

    # scc result:
    # mean(u) = 369.090945721
    # mean(ptime) = 172.3960495

    # COCONUT result:
    # mean(u) = 704.527628542
    # mean(ptime) = 448.962222446

    # CU result:
    # mean(u) = 625.116920471
    # mean(ptime) = 378.924741745




    """
    filepath = '/home/shengliu/Workspace/mininet/haha/API/flow_update.tsv'
    K = 4
    path_list = path_read(filepath, K)
    flow_list = {}
    line_num = []
    #print path_list
    ct = 0
    for j in range(len(path_list['flow'])):
        i = path_list['flow'][j]
        f = match_parse(i)
        f_reverse = match_parse(reverse_flow(i))
        if f not in flow_list.keys() and f_reverse not in flow_list.keys():
            flow_list[f] = path_list['new_path'][j]['path']
            line_num.append(j)
            #flow_list[x1].append(path_list['new_path'])
        else:
            if f in flow_list.keys():
                y = f
            else:
                if f_reverse in flow_list.keys():
                    y = f_reverse
            if flow_list[y] != path_list['old_path'][j]['path']:
                if y == match_parse(path_list['flow'][0]) or y == match_parse(reverse_flow(path_list['flow'][0])):
                    #print i
                #print
                    print "cao"
                    print j
                #print flow_list[y]
                #print path_list['old_path'][j]['path']
                ct = ct + 1
            else:
                flow_list[y] = path_list['new_path'][j]['path']
                if y == match_parse(path_list['flow'][0]) or y == match_parse(reverse_flow(path_list['flow'][0])):
                    #print i
                #print
                    print j

    print ct
    print len(flow_list.keys())
    #print len(flow_list)
    #print flow_list
    #for i in flow_list:
    #    if i.reverse in flow_list:
    #        print i
    """
