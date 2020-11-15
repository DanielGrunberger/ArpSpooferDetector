from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from python_arptable import get_arp_table


def isDuplicatedMAC():
     arp_table = get_arp_table()
     #print(arp_table)
     for index in range(0, len(arp_table)):
        current_MAC = arp_table[index]['HW address']
       # print(current_MAC)
        if index == len(arp_table):
            return False
        for i in range(index+1, len(arp_table)):
            MAC = arp_table[i]['HW address']
        #    print(MAC)
            if current_MAC == MAC:
                return True




def getRealMAC(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc



def isArpSpoofing(packet):
    # if it is an ARP response (ARP reply)
    condition1 = False
    condition2 = False
    if packet[ARP].op == 2:
        real_mac = getRealMAC(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if real_mac != response_mac:
            condition1 = True

    condition2 = isDuplicatedMAC()
#    print(condition1)
#   print(condition2)
    if condition2 and condition1:
        print("Arp spoof going on !!!!")
        #exit()







isDuplicatedMAC()

sniff(prn=isArpSpoofing, lfilter=lambda x: x.haslayer(ARP), count=0, store=False)