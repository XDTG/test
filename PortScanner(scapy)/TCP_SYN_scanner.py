#coding:utf-8
#TCP SYN扫描
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def tcp_syn_scan(dst_ip,dst_port,dst_timeout=10):
	src_port = RandShort()

	stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=dst_timeout)
	if(type(stealth_scan_resp)==type(None)):
		return 'Filtered'
	elif(stealth_scan_resp.haslayer(TCP)):
		if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='R'),timeout=dst_timeout)
			return 'Open'
		elif(stealth_scan_resp.getlayer(TCP).flags == 0x4):
			return 'Closed'
	elif(stealth_scan_resp.haslayer(ICMP)):
	#如果服务器返回了一个 ICMP 数据包，其中包含 ICMP 目标不可达错误类型3以及 ICMP 状态码为1，2，3，9，10或13，则说明目标端口被过滤了无法确定是否处于开放状态
		if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 'Filtered'
		

dst_ip = '220.181.57.216'
dst_port = 80

if __name__ == '__main__':
	print tcp_syn_scan(dst_ip,dst_port)