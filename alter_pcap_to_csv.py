# coding=utf-8

import os
import re
import sys
import time
import struct


def parse_pcap_dir(pcap_path, alert_tup_lst, sid_num, sid_rule_dic, tg_dr):
    for rt, _, fls in os.walk(pcap_path):
        for fl in fls:
            if fl.endswith('.pcap'):
                pcap_fl = os.path.join(rt, fl)
                th_sid = parse_pcap_fl(pcap_fl, alert_tup_lst)
                if th_sid != {}:
                    write_to_csv(alert_tup_lst, sid_num, sid_rule_dic, th_sid, pcap_fl, tg_dr)


def write_to_csv(alert_tup_lst, sid_num, sid_rule_dic, th_sid, pcap_fl, tg_dr):
    i = 0
    for th, alert_tup_lst in th_sid.items():
        for alert_tup in alert_tup_lst:
            src_ip = alert_tup[3]
            src_ip = str(alert_tup[3])
            tg = os.path.join(tg_dr, src_ip.replace('.', ':'))
            if not (os.path.exists(tg + '.csv') and os.path.isfile(tg + '.csv')):
                with open(tg + '.csv', 'a+') as fp:
                    fp.write("应用名称,应用版本,名称特征,名称特征出现次数,名称特征出现位置,版本特征,版本特征出现位置\r\n")
            with open(tg + '.csv', 'a+') as fp:
                i += 1
                w_line = (alert_tup[1] +  ',\"' + '' + '\",\"' + sid_rule_dic[alert_tup[0]]
                        + '\",\"' + str(sid_num[alert_tup[0]]) + '\",\"' + pcap_fl + '第' + str(th)
                        + '个包' + '\",\"' + sid_rule_dic[alert_tup[0]] + '\",\"' + pcap_fl + '第' + str(th)
                        + '个包'
                        + '\"''\r\n')
                fp.write(w_line)
    print 'DONE:', i


def parse_pcap_fl(pcap_path, alert_tup_lst):
    th_sid = {}
    fpcap = open(pcap_path,'rb')
    string_data = fpcap.read()   
    i = 24
    packet_num = 0
    j = 0
    k = 0
    while(i < len(string_data)):
        package_information = {}
        packet_num += 1
        GMTtime = struct.unpack('I', string_data[i:i+4])[0]
        MicroTime = struct.unpack('I', string_data[i+4:i+8])[0]
        
        package_information['src_ip'] = str(int(hex(ord(string_data[i+42:i+43])),16))
        for index in range(1,4):
            package_information['src_ip'] += ':'
            package_information['src_ip'] += str(int(hex(ord(string_data[i+42+index:i+43+index])),16))
        package_information['dst_ip'] = str(int(hex(ord(string_data[i + 46:i + 47])), 16))
        for index in range(1,4):
            package_information['dst_ip'] += ':'
            package_information['dst_ip'] += str(int(hex(ord(string_data[i+46+index:i+47+index])),16))
        
        """
        # cmp_tm(tm1, tm2_1, tm2_2):
        # if tm1 < tm2 return -1
        # if tm1 == tm2 return 0
        # if tm1 > tm2 return 1
        """
        while j < len(alert_tup_lst) and cmp_tm(alert_tup_lst[j][2], GMTtime, MicroTime) == -1:
                j += 1

        while j < len(alert_tup_lst) and equal(package_information, GMTtime, MicroTime, alert_tup_lst[j]):
            th_sid.setdefault(packet_num, []).append(alert_tup_lst[j])
            print 'GOT ONE:',packet_num
            k += 1
            j += 1
        
        packet_len = struct.unpack('I',string_data[i+12:i+16])[0]
        i = i + packet_len + 16
    print 'TOTAL:', k
    
    return th_sid


def equal(package_information, GMTtime, MicroTime, tup):
    return (
        cmp_tm(tup[2], GMTtime, MicroTime) == 0 
        and package_information['src_ip'] == tup[3].replace('.', ':')
        and package_information['dst_ip'] == tup[4].replace('.', ':')
    )


def cmp_tm(time_snort, GMTtime, MicroTime):
    timestamp = float(str(GMTtime))
    time_local = time.localtime(timestamp)
    time_lst = time_snort.split('.')
    dt = time.strftime("%02m/%02d-%02H:%02M:%02S", time_local)
    if time_lst[0] == dt and int(time_lst[1]) == (MicroTime):
        return 0
    elif time_lst[0] > dt or (time_lst[0] == dt and int(time_lst[1]) > (MicroTime)):
        return 1
    else:
        return -1 


def parse_rule(filename, rule):
    sid_rule_dic = {}
    with open(filename) as fp, open(rule) as fr:
        content = fp.read()
        pattern = '\[\*\*\] \[.*:(.*?):.*\].*?'
        sid_lst = re.findall(pattern, content)
        pat_line_sid = '.*sid: (.*?);'
        for line in fr:
            sid = re.findall(pat_line_sid, line)[0]
            if sid in sid_lst:
                sid_rule_dic[sid] = line.strip()   
    
    return sid_rule_dic


def parse_alert(alter):
    i = 0
    ret_lst = []
    with open(alter) as fp:
        packet = []
        for line in fp:
            i += 1
            pattern = '\[\*\*\] \[.*:(.*?):.*\].*?'
            sid = re.findall(pattern, line)
            if sid != []:
                i = 1
                packet.append(sid[0])
                packet.append(line.split()[2])
            elif i  == 3:
                lst = line.split()
                tm = lst[0]
                src_ip = lst[1].split(':')[0]
                src_port = lst[1].split(':')[1]
                dst_ip = lst[3].split(':')[0]
                dst_port = lst[3].split(':')[1]
                packet.append(tm)
                packet.append(src_ip)
                packet.append(dst_ip)
                packet.append(src_port)
                packet.append(dst_port)
            elif i == 5:
                ret_lst.append(tuple(packet))
                packet = []
    sid_num = {}
    for tup in ret_lst:
        sid_num[tup[0]] = sid_num.get(tup[0], 0) + 1

    return ret_lst, sid_num


if __name__ == '__main__':
    # path = '/alert'
    # rule = '/etc/snort/rules/iqiyi.rules'
    # target = 'new.rules'
    
    # alert file
    alert_fl = sys.argv[1]
    # .rules file
    rule = sys.argv[2]
    # pcap dir
    pcap_path = sys.argv[3]
    # save target file
    tg_dr = sys.argv[4]
    
    alert_tup_lst, sid_num = parse_alert(alert_fl)
    sid_rule_dic = parse_rule(alert_fl, rule)    
    parse_pcap_dir(pcap_path, alert_tup_lst, sid_num, sid_rule_dic, tg_dr)

    print len(alert_tup_lst)