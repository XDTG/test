#coding:utf-8
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def fin_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='F'),timeout=dst_timeout)
	if(type(fin_scan_resp)==type(None)):
		return 'Open|Filtered'
	elif(fin_scan_resp.haslayer(TCP)):
		if(fin_scan_resp.getlayer(TCP).flags==0x4):
			return 'Closed'
	elif(fin_scan_resp.haslayer(ICMP)):
		if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 'Filtered'


dst_ip = '220.181.57.216'
dst_port = 80

print fin_scan(dst_ip,dst_port)