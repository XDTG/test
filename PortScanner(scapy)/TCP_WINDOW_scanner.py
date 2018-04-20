#coding:utf-8

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def tcp_window_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	window_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='A'),timeout=dst_timeout)
	if(type(window_scan_resp)==type(None)):
		return 'No response'
	elif(window_scan_resp.haslayer(TCP)):
		if(window_scan_resp.getlayer(TCP).window==0):
			return 'Closed'
		elif(window_scan_resp.getlayer(TCP).wandow>0):
			return 'Open'


dst_ip = "220.181.57.216"
dst_port=80

if __name__ == '__main__':
	print tcp_window_scan(dst_ip,dst_port)