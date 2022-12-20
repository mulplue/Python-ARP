"""
    Implemented by Jiahe Chen.
"""
import re
from subprocess import PIPE, Popen
import tkinter.messagebox
import os
import time

# 根据获取到的IP网卡地址，获知对应的网卡名字
def ip_to_name(ip):
    command1 = r'ipconfig'
    interface_name1 = ''  # 获取到网卡的名字
    p = Popen(command1, stdout=PIPE, stderr=PIPE)
    stdout1, stderr1 = p.communicate()

    ipconfig = stdout1.decode('gbk')
    a = ipconfig.split('网适配器')
    del (a[0])
    for i1 in a:
        if '断开连接' not in i1 and ip in i1:
            interface_msg = i1.split('子网掩码')[0]  # 获取每个网卡的网络信息，断开连接的网卡不予展示
            interface_name1 = interface_msg.split('连接特定的 DNS 后缀')[0].replace(':', '').strip()  # 获取到网卡的名字
    return interface_name1

def work():
    desktop_path = os.path.join(os.path.expanduser("~"), 'Desktop')  # 获取桌面路径
    path_result = os.path.join(desktop_path, 'evil_arp.txt')  # 用来存储终端中输出的内容到一个文本中，方便用户使用数据，此为文本路径
    path_result1 = os.path.join(desktop_path, 'arp.txt')  # 用来存储终端中输出的内容到一个文本中，方便用户使用数据，此为文本路径
    evil_arp = ''  # 用来记录所有的可疑arp表项
    flag = 0
    command = r'arp -a'
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    arp_form = stdout.decode('gbk')

    arp_list = arp_form.split('接口:')
    for i2 in arp_list:  # 把ARP表按照网卡进行切分
        ip_and_mac = {}  # 用来存放arp小表中的IP和MAC地址
        mac_list = []  # 用来存储一个ARP小表中的所有mac，借此检查有无重复的mac，进而得知ARP攻击

        interface_arp = i2.split('---')[0].strip()  # 获取每个ARP小表的网卡地址

        # 从每一个ARP小表中提取出IP地址和MAC地址，将其绑定为字典
        obj = re.compile(r"(?P<ip>(\d+\x2e){3}\d+)\s+(?P<mac>(\w\w-){5}\w\w)", re.S)
        result = obj.finditer(i2)
        for i3 in result:
            # print(i3.group('ip'), i3.group('mac'), sep=' ')
            ip_and_mac[i3.group('ip')] = i3.group('mac')

        # 判断有误重复的MAC地址
        for i4 in ip_and_mac.values():
            if i4 == 'ff-ff-ff-ff-ff-ff':
                pass
            else:
                if i4 not in mac_list:
                    mac_list.append(i4)
                else:
                    flag = 1
                    interface_name = ip_to_name(interface_arp)  # 获知网卡名字
                    repeat_ip = [k for k, v in ip_and_mac.items() if v == i4]  # 获知重复MAC对应的IP
                    msg = ''
                    for ri in repeat_ip:
                        msg += ri + '\t' + i4 + '\n'

                    alert_msg = interface_name + '网卡 发现ARP攻击！\n' + msg
                    evil_arp += alert_msg + '\n'
                    tkinter.messagebox.showerror('ARP攻击！ARP记录已存放至桌面！', alert_msg)

    # 导出结果
    if flag:
        # 导出所有的ARP记录
        a = open(path_result, 'w', encoding='utf8')
        for r in evil_arp:
            a.write(r)
        a.close()

        # 导出可疑的ARP记录
        arp_record = r'arp -a > ' + path_result1
        os.system(arp_record)

if __name__ == '__main__':
    '''
    脚本功能：每隔一段时间查询一次ARP表，一旦发现ARP异常，就会导出结果到桌面
    '''
    while True:
        work()
        time.sleep(1*60)  # 每隔1分钟运行一次
