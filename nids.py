#!/usr/bin/python
# simple Network Intrussion Detection System using
# raw_socket module (please running this script example
# with sudo/root because raw socket must be root
# priviledge
#
# Algorthm i use string matching for match text filter_string on ip header data = packet
# if re.search(filter_string,packet):doing
# adopt from my code network packet sniffer
#-----------------------------------------------

import socket
import sys
from struct import *
import string
import re  
import time
from datetime import datetime

def proses(socket_setup,filter_string):
	# fungsi untuk menerima data, kita set jumlah byte yg diperbolehkan 
    packet = socket_setup.recvfrom(65565) 
	#packet string from tuple
    packet = packet[0] 
	#take first 20 characters for the ip header
    ip_header = packet[0:20]
	#now unpack them for ip header
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
	version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
    
    ttl = iph[5]
    protocol = iph[6]    
	s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
	
	#now unpack them for tcp header
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
	
    try:
         log_file = open('blacklist_ip.log','a+')
    except:
         print 'file tidak ditemukan'
	
	try:
       if re.search(filter_string,packet):
		  print 'Alert Ditemukan Filter String : ' + filter_string
          print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
		  print 'Source Port : ' + str(source_port) + ' Destination Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
		  print 'Waktu Alert'  + str(datetime.now())
		  
		  h_size = iph_length + tcph_length * 4
		  data_size = len(packet) - h_size
		  #get data from the packet
		  data = packet[h_size:]
		  print 'Data : ' + data
		  print
		  
		  ip_s = socket.getfqdn(s_addr)
		  log_file.write(ip_s+'\n')
          print data_get
          log_file.close()
		  # add prevention method after found the alert filter
		  
		  
		  
    except Exeption ,err:
       print [err]
       
def main():
    socket_setup = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    filter_string = raw_input('Input Filter String :')
    while True:
       try:
         proses(socket_setup,filter_string)
       except Exception ,er:
         print er
         sys.exit()
         break
         
if __name__ == "__main__":
     main()
