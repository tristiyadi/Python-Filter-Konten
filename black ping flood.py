#!/usr/bin/python
# Simple Network Intrussion Prevention System
# Sample Case: Ping Flooding
#
# Module Requirement: python-pcapy
# testing on Ubuntu
#
# coded by: 5ynL0rd


import pcapy
import re
import binascii
import os
import json

from datetime import datetime

class VoidSniff:
    def __init__(self, pcap_filter):
         self.device = "any"  
         self.snaplen = 2048    
         self.promisc = 1     
         self.to_ms = 100        
         self.pcap_filter = pcap_filter
         self.max_pkts = -1
         self.p = pcapy.open_live(self.device, self.snaplen, self.promisc, self.to_ms)
         
    def packethandler(self, hdr, data):
         byte = len(data)
         timestamp = datetime.now()
         contain = binascii.b2a_hex(data)
         src_ip = '%s.%s.%s.%s' %(int('0x'+contain[56:58], 0),int('0x'+contain[58:60], 0),int('0x'+contain[60:62], 0),int('0x'+contain[62:64], 0))
         dst_ip = '%s.%s.%s.%s' %(int('0x'+contain[64:66], 0),int('0x'+contain[66:68], 0),int('0x'+contain[68:70], 0),int('0x'+contain[70:72], 0))
         src_port = str(int('0x'+contain[72:76], 0))
         dst_port = str(int('0x'+contain[76:80], 0))
         
         # PING Flooding Detection
         if self.pcap_filter == 'icmp':
             data = [{'ip': src_ip,
                      'timestamp': '%s-%s-%s-%s-%s-%s-%s' % (datetime.utcnow().year,
                                                                datetime.utcnow().month,
                                                                datetime.utcnow().day, 
                                                                datetime.utcnow().hour, 
                                                                datetime.utcnow().minute,
                                                                datetime.utcnow().second,
                                                                datetime.utcnow().microsecond
                                                                ),
             }]
             data = json.dumps(data)

             try:
                 data_prev = open('dump.json', 'r').read()
             except Exception, err:
                 open('dump.json', 'w').write(data)
             else:
                 data_prev = json.loads(data_prev)
                 data = json.loads(data)
                 data = data_prev + data
                 open('dump.json', 'w').write(json.dumps(data))
                 
             try:
                 blacklist = open('blacklist.json', 'r').read()
             except Exception, err:
                 blacklist = []
             else:
                 blacklist = json.loads(blacklist)
                 
             data_from_json = open('dump.json','r').read()
             data_from_json = json.loads(data_from_json)
             if len(data_from_json) >= 50 and {'ip': src_ip} not in blacklist:
                 first = data[0]['timestamp']
                 delta = datetime.utcnow() - datetime(int(first.split('-')[0]),
                                                          int(first.split('-')[1]),
                                                          int(first.split('-')[2]),
                                                          int(first.split('-')[3]),
                                                          int(first.split('-')[4]),
                                                          int(first.split('-')[5]),
                                                          int(first.split('-')[6]))
                 if delta.seconds == 0:
                     print '[!] ALERT! PING FLOODING FROM: %s' % src_ip
                     b_data = json.dumps([{'ip':src_ip}])
                     try:
                         b_data_prev = open('blacklist.json', 'r').read()
                     except Exception:
                         pass
                     else:
                         b_data = json.loads(b_data_prev) + json.loads(b_data)
                         b_data = json.dumps(b_data)
                     open('blacklist.json', 'w').write(b_data)
                     os.system('iptables -A FORWARD -s %s -p icmp -j DROP' % src_ip)
                     os.system('iptables -A OUTPUT -s %s -p icmp -j DROP' % src_ip)
                     print '[!] IP %s Blocked!' % src_ip
                 os.remove('dump.json')

         
    def run(self):
         self.p.setfilter(self.pcap_filter)
         self.p.loop(self.max_pkts, self.packethandler)

if __name__ == '__main__':    
    icmp_sniff = VoidSniff('icmp')
    icmp_sniff.run()
