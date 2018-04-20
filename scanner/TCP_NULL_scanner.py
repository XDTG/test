#coding:utf-8
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def null_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	null_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags=''),timeout=dst_timeout)
	if(type(null_scan_resp)==type(None)):
		return 'Open|Filtered'
	elif(null_scan_resp.haslayer(TCP)):
		if(null_scan_resp.getlayer(TCP).flags==0x4):
			return 'Closed'
	elif(null_scan_resp.haslayer(ICMP)):
		if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 'Filtered'


dst_ip = '220.181.57.216'
dst_port = 80

if __name__ == '__main__':
	print null_scan(dst_ip,dst_port)