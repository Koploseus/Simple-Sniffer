import sys
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *
from scapy.all import IP, sniff
from scapy.layers import http
from multiprocessing import Process
from threading import Thread


interface = sys.argv[1]

usernames = ['']
passwords = ['']


def process_intercept(origin, dsthost, dstpath, dstmethod):
    print ("*"*69)
    print ('\n{0} just requested a {1} {2}{3}'.format(origin, dstmethod, dsthost, dstpath))


def process_tcp_packet(pkt):
    if not pkt.haslayer(http.HTTPRequest):
        return
    http_layer = pkt.getlayer(http.HTTPRequest)
    ip_layer = pkt.getlayer(IP)
    process_intercept(ip_layer.fields['src'], http_layer.fields['Host'], http_layer.fields['Path'], http_layer.fields['Method'])
    print ("[+] HTTP sent to %s : %s" % (pkt.payload.dst, http_layer[1]))



def check_login(pkt, username, password):
	if b'230' in pkt[Raw].load:
		print ('[*] Valid FTCredentials Found... ')
		print ('\t[*] ' + str(pkt[IP].dst).strip() + ' -> ' + str(pkt[IP].src).strip() + ':')
		print ('\t   [*] Username: ' + str(username))
		print ('\t   [*] Password: ' + str(password) + '\n')
		return
	else:
		return


def check_for_ftp(pkt):
	if pkt.haslayer(TCP) and pkt.haslayer(Raw):
		if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
			return True
		if pkt[TCP].dport == 80:
                        process_tcp_packet(pkt)
                
		else:
			return False
	else:
		return False

def check_pkt(pkt):
	conf.verb = 0
	if check_for_ftp(pkt):
		pass
	else:
		return
	data = pkt[Raw].load
	if b'USER ' in data:
		usernames.append(data.split(b'USER ')[1].strip())
	elif b'PASS ' in data:
		passwords.append(data.split(b'PASS ')[1].strip())
	else:
		check_login(pkt, usernames[-1], passwords[-1])
		return
