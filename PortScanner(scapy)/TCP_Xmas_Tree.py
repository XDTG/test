#coding:utf-8
#TCP 圣诞树(Xmas Tree)扫描

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def xmas_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags='FPU'),timeout=dst_timeout)
	if(type(xmas_scan_resp)==type(None)):
		return 'open|Filtered'
	elif(xmas_scan_resp.haslayer(TCP)):
		if(xmas_scan_resp.getlayer(TCP).flags==0x4): #flags==RST
			return 'Closed'
	elif(xmas_scan_resp.haslayer(ICMP)):
		if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 'Filtered'
		
dst_ip = '220.181.57.216'
dst_port = 80

if __name__ == '__main__':
	print xmas_scan(dst_ip,dst_port)