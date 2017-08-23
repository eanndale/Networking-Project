#!/usr/bin/env python
#Source: https://github.com/jrguo/SYN-Scan-Detection/blob/master/analyze.py

import dpkt
import sys
import socket
import json
import time

def main():
	if len(sys.argv) > 2:
		return
	
	pcap_file = open(sys.argv[1], 'rb')
	pcap = dpkt.pcap.Reader(pcap_file)
	count = 0
	ip_dict = {}

	for ts, buf in pcap:
		
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip_hdr = eth.data


			if ip_hdr.p == dpkt.ip.IP_PROTO_TCP: #Check for TCP packets

				tcp = ip_hdr.data 
				syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
				ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
				src_ip_addr_str = socket.inet_ntoa(ip_hdr.src)
				dst_ip_addr_str = socket.inet_ntoa(ip_hdr.dst)

				if syn_flag and not ack_flag:

					if src_ip_addr_str in ip_dict:
						ip_dict[src_ip_addr_str]['SYN'] += 1
					else:
						ip_dict[src_ip_addr_str] = {'SYN':1,'SYN-ACK':0}
						
				if syn_flag and ack_flag:

					if dst_ip_addr_str in ip_dict:
						ip_dict[dst_ip_addr_str]['SYN-ACK'] += 1
					else:
						ip_dict[dst_ip_addr_str] = {'SYN':0,'SYN-ACK':1}
						

		except Exception as e:
			pass

	pcap_file.close()	

	vul = {}
	for key in ip_dict.keys():
		vul[key] = ip_dict[key]['SYN'] - 3*ip_dict[key]['SYN-ACK'] > 0

	for ip in vul:
		if vul[ip]:
			print (ip)

if __name__ == "__main__":
    main()