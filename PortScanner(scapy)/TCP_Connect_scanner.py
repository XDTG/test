# -*- coding: UTF-8 -*-
#TCP scanner

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

dst_ip = '220.181.57.216'
dst_port=80

def tcp_connect_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=dst_timeout)
	if(type(tcp_connect_scan_resp)==type(None)):   #error: ==""
	    return "Filtered"
	elif(tcp_connect_scan_resp.haslayer(TCP)):
	    if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12): #flags=='AS'
	        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
	        return "Open"
	elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x4):#flags=='R'
	    return "Closed"

dst_ip = '220.181.57.216'
src_port = RandShort()
dst_port=80

if __name__ == '__main__':
	print tcp_connect_scan(dst_ip,dst_port)