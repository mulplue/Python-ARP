"""
    Implemented by Jiahe Chen.
"""
import sys
import os
import time
import _thread
import datetime
import nmap
import netifaces

def get_gateways():
    """Get gateway of this LAN
    Return:
        gateway: Default gateway
    """
    gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    return gateway

def ping_ip(ip_str):
    """Ping IP adress
    Args:
        ip_str: String form of ipv4 address
    Return:
        None
    """
    ## send command
    cmd = ["ping", "-{op}".format(op="c"), "1", ip_str]
    output = os.popen(" ".join(cmd)).readlines()
    ## check
    flag = False
    for line in list(output):
        if not line:
            continue
        if str(line).upper().find("TTL") >=0:
            flag = True
            break
    ## print device
    if flag:
        nmScan = nmap.PortScanner()
        nmScan.scan(hosts=ip_str, arguments='-sP')
        print("--------------------ip: %s is OK--------------------"%(ip_str))
        print(nmScan[ip_str])

def find_ip(ip_prefix):
    """Scan from ip_prefix.1 to ip_prefix.255
    Args:
        ip_prefix: 3rd prefix of an ipv4 address, for example: '192.168.41.'
    Return:
        None
    """
    for i in range(1,256):
        ip = ('%s%s'%(ip_prefix,i))
        _thread.start_new_thread(ping_ip, (ip,))
        time.sleep(0.3)

if __name__ == "__main__":
    ## Start
    startTime = datetime.datetime.now()
    print("start time %s"%(time.ctime()))
    ## Get gateway prefix
    gateway = get_gateways()
    ip_nums = gateway.split('.')
    gateway_prefix = str(ip_nums[0]) + '.' + str(ip_nums[1]) + '.' + str(ip_nums[2]) + '.'
    ## Scan
    find_ip(gateway_prefix)
    ## End
    endTime = datetime.datetime.now()
    print("end time %s"%(time.ctime()))
    print("total takes :",(endTime - startTime).seconds, "(s)")