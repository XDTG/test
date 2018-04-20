#coding:utf-8
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

def tcp_ack_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	ack_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='A'),timeout=dst_timeout)
	if(type(ack_scan_resp)==type(None)):
		return 'Stateful firewall present(Filtered)'
	elif(ack_scan_resp.haslayer(TCP)):
		if(ack_scan_resp.getlayer(TCP).flags==0x4):
			return 'No firewall(Unfiltered)'
	elif(ack_scan_resp.haslayer(ICMP)):
		if(ack_scan_resp.getlayer(ICMP).tpye==3 and int(ack_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 'Stateful firewall present(Filtered)'

dst_ip = '220.181.57.216'
dst_port = 80

if __name__ == '__main__':
	print tcp_ack_scan(dst_ip,dst_port)