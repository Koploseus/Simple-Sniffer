from __future__ import print_function
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)#Une erreur apparait, ce bout de code permet de l'enlever
from scapy.all import get_if_addr, conf
import subprocess
from multiprocessing import Process
import sys
import time
import os
import argparse
import arpreq
import netifaces as ni


FNULL = open(os.devnull, 'w')


interface = sys.argv[1]


class multi_ping(object):
	def __init__(self):
		self.multi_pinger.__init__(self)


	def pinger(self, host_num):
		ni.ifaddresses(interface)
		ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

		hostadrr = ip.split('.')[:-1]
		hostadrr = '.'.join(hostadrr) + '.' + repr(host_num)

		line = subprocess.getoutput("ping -n -c 1 %s 2> /dev/null" % hostadrr)
		time.sleep(2)

		while True:
			if line.find(hostadrr) and line.find("bytes from") > -1:  # Host Active
				is_active = []
				is_active.append(hostadrr)
				alive_host = is_active.pop()

				print("Host %s is \033[92m Active \033[0m" % alive_host)
				with open('result_ping.txt', 'a+') as the_file:
    					the_file.write(alive_host + ' -- ' + arpreq.arpreq(alive_host))
    					the_file.write("\n")
				break
			else:
				exit(0)

	def multi_pinger(self):
		for host_num in range(1, 255):
			ping = Process(target=self.pinger, args=(host_num,))
			ping.start()


if __name__ == '__main__':
	try:
		print("--------------------------------------")
		print("")
		print("\033[92mProbe on start\033[0m")
		print("--------------------------------------")
		print("")
		print("Scan in \033[92mProgress \033[0m")
		time.sleep(2)

		multi_ping().multi_pinger()
	except KeyboardInterrupt:
		pass
