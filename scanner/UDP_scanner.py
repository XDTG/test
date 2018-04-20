#coding:utf-8

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *


def udp_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()
	
	udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(sport=src_port,dport=dst_port),timeout=dst_timeout)
	if(type(udp_scan_resp)==type(None)):
		print '无回复,进行重试'
		retrans = []
		for i in range(0,3):
			retrans.append(sr1(IP(dst=dst_ip)/UDP(sport=src_port,dport=dst_port),timeout=dst_timeout))
			if(type(retrans[i])!=type(None)):
				udp_scan_resp=retrans[i]  
				break                            #重试三次
			else:
				print '第%d次重试无回复'%(i+1)
	return 'Open|Filtered'
	if(udp_scan_resp.haslay(UDP)):
		return 'Open'
	elif(udp_scan_resp.haslay(ICMP)):
		if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
			return 'Closed'
		elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
			return 'Filtered'

dst_ip = "220.181.57.216"
dst_port=80

if __name__=='__main__':
	print udp_scan(dst_ip,dst_port)