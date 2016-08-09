import os
import logging
import binascii
import re
import sys
import threading
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)      # Delete scapy logging
from scapy.all import *

myMAC = ""
gatewayMAC = ""

def open_list():
	f = open("mal_site.txt", "r")
	mal_site = f.read().split('\n')
	print mal_site
	f.close()

def http_parse(data):
	str_method = ""
	str_uri = ""
	
	h = re.search("(?P<method>(^GET|^POST|^PUT|^DELETE)) (?P<uri>.+) (?P<version>.+)", data)
	if not h: return "Error"

	if h.group("method"): str_method = h.group("method")
	if h.group("uri"): str_uri = h.group("uri")

	return str_method,str_uri
	

def proc(packet):
	p = packet[0]
	layer = p.payload
	while layer:
		layerName = layer.name
		if layerName == "Raw":
			result = http_parse(layer.load)
			if result != "Error":
				print result[0] + " " + result[1]
		layer = layer.payload


class capture(threading.Thread):
	def run(self):
		global myMAC, gatewayMAC
		while(True):
			sniff(prn=proc, filter="(ether src host " + myMAC + ") and (ether dst host " + gatewayMAC + ")", count=1)

def main():
	global myMAC, gatewayMAC
	myMAC = os.popen("ifconfig eth0 | awk '/HWaddr/ { print $5 }'").read().replace('\n','')	
	arp_stat = os.popen("arp -a").read()
	gatewayIP = os.popen("route | awk '/default/ { print $2 }'").read().replace('\n','')
	gatewayMAC = re.findall("\("+str(gatewayIP)+"\) at ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}) \[ether\]", arp_stat)
	if gatewayMAC:
		gatewayMAC = gatewayMAC[0]
	else:
		print "Can't get gatewayMAC!"
		sys.exit(0)

		
	open_list()
	tCapture = capture()
	tCapture.start()
	tCapture.join()

if __name__ == "__main__":
	main()
