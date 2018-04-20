#coding=utf-8
import socket
import threading
import Queue
import sys

class DoRun(threading.Thread):
	def __init__(self,queue):
		threading.Thread.__init__(self)
		self._queue = queue

	def run(self):
		while not self._queue.empty():
			key = self._queue.get()
			PortScan('111.13.101.208',key,1)


def PortScan(ipaddr,port_number,delay):
	#creat a socket
	TCP_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	TCP_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
	TCP_sock.settimeout(delay)

	try:
		result = TCP_sock.connect_ex((ipaddr,int(port_number)))

		if result == 0:
			sys.stdout.write('%s  OPEN\n'%port_number) 
		else:
			sys.stdout.write('%s  CLOSE\n'%port_number) 

		TCP_sock.close()
	except socket.error as e:
		sys.stdout.write('%s  CLOSE\n'%port_number) 

#
def main():
	threads = []
	threads_count = 100
	queue = Queue.Queue()

	for i in range(0,1000):
		queue.put(i)
	for i in range(threads_count):
		threads.append(DoRun(queue))
	for i in threads:
		i.start()
	for i in threads:
		i.join()



if __name__ == '__main__':
	main()