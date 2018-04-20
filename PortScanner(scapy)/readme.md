
this is a scapy_scanner repository.

代码主要参考了 http://www.freebuf.com/sectool/94507.html  --如何用Scapy写一个端口扫描器？ 

修改了部分错误：
	RST回复包flags应该为0x4
               
优化了部分功能：
	所有扫描器均为一个函数形式可被调用
	UDP扫描重试机制进行了改善

部分函数和变量解释：
    RandShort()：产生随机数 
    type()：获取数据类型 
    sport：源端口号
    dport：目标端口号
    timeout：等待相应的时间
    haslayer()：查找指定层：TCP或UDP或ICMP
    getlayer()：获取指定层：TCP或UDP或ICMP
