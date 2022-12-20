"""
    Implemented by Jiahe Chen.
"""
import re
from subprocess import PIPE, Popen
import os
import time

def ip_to_name(ip):
    """Get iface from IP adress
    Args:
        ip: IPV4 adress of network card
    Return
        iface_name: interface name of network card
    """
    command1 = r'ipconfig'
    iface_name = ''
    p = Popen(command1, stdout=PIPE, stderr=PIPE)
    stdout1, stderr1 = p.communicate()

    ipconfig = stdout1.decode('gbk')
    a = ipconfig.split('网适配器')
    del (a[0])
    for i1 in a:
        if '断开连接' not in i1 and ip in i1:
            interface_msg = i1.split('子网掩码')[0]
            iface_name = interface_msg.split('连接特定的 DNS 后缀')[0].replace(':', '').strip()
    return iface_name

def main(record_path):
    """Detect ARP attacks
    """
    ## init
    path_result = os.path.join(record_path, 'evil_arp.txt')
    path_result1 = os.path.join(record_path, 'arp.txt')
    evil_arp = ''
    flag = 0
    ## make command and get information
    command = r'arp -a'
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    arp_form = stdout.decode('gbk')
    arp_list = arp_form.split('接口:')
    ## get arp infomation in line
    for i2 in arp_list: 
        ip_and_mac = {} 
        mac_list = []
        interface_arp = i2.split('---')[0].strip()
        ## make {ip: mac} dict
        obj = re.compile(r"(?P<ip>(\d+\x2e){3}\d+)\s+(?P<mac>(\w\w-){5}\w\w)", re.S)
        result = obj.finditer(i2)
        for i3 in result:
            ip_and_mac[i3.group('ip')] = i3.group('mac')

        ## judge same mac address
        for i4 in ip_and_mac.values():
            if i4 == 'ff-ff-ff-ff-ff-ff':
                pass
            else:
                if i4 not in mac_list:
                    mac_list.append(i4)
                else:
                    flag = 1
                    interface_name = ip_to_name(interface_arp)
                    repeat_ip = [k for k, v in ip_and_mac.items() if v == i4]  # get ip of same mac
                    msg = ''
                    for ri in repeat_ip:
                        msg += ri + '\t' + i4 + '\n'
                    ## report
                    alert_msg = interface_name + '网卡 发现ARP攻击！\n' + msg
                    evil_arp += alert_msg + '\n'
                    print(alert_msg)

    # export results
    if flag:
        # all ARP results
        a = open(path_result, 'w', encoding='utf8')
        for r in evil_arp:
            a.write(r)
        a.close()

        # suspected ARP results
        arp_record = r'arp -a > ' + path_result1
        os.system(arp_record)

if __name__ == '__main__':
    record_path = '../record'   # record path
    interval = 60               # detect intercal
    while True:
        main(record_path)
        time.sleep(interval)
