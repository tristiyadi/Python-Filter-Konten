#!/usr/bin/python
# simple Network Intrussion Detection System using 
# pcapy module (please running this script example 
# with sudo/root because raw socket must be root 
# priviledge
#
#
# download pcapy in ur Ubuntu:
# $ sudo apt-get install python-pcapy
# or (if u have pip)
# $ sudo pip install pcapy


import pcapy
import re
import binascii
import socket

class VoidSniff:
    def __init__(self, filt):
         self.device = "any"  
         self.snaplen = 2048    
         self.promisc = 1     
         self.to_ms = 100        
         self.pcap_filter = ""    
         self.max_pkts = -1         
         self.filterstring = filt
         self.p = pcapy.open_live(self.device, self.snaplen, self.promisc, self.to_ms)
#konversi ke IP address
    def conv(self, s):
        self.IP = str(self.hex2dec(s[0:2]))+'.'+str(self.hex2dec(s[2:4]))+'.'+\
                  str(self.hex2dec(s[4:6]))+'.'+str(self.hex2dec(s[6:8]))
        return self.IP

    def hex2dec(self, x):
        return int('0x'+x, 0)

    def packethandler(self, hdr, data):
        if re.search(self.filterstring, data):
            contain = binascii.b2a_hex(data)
            ip_s = self.conv(contain[56:64])
            try:
                dom_s = socket.getfqdn(ip_s)
            except:
                dom_s = ip_s
            try:
                logger = open('block.log','a+')
            except:
                print 'file not found'
            else:
                if re.search(dom_s,logger.read()):
                    pass
                else:
                    logger.write(dom_s+'\n')
                    print 'Logged IP: '+dom_s
                    logger.close()
            print '[+] alert ditemukan! '
            # u can add prevention method after found the pattern attack

    def run(self):
         self.p.setfilter(self.pcap_filter)
         self.p.loop(self.max_pkts, self.packethandler)

if __name__ == '__main__':
    filter = raw_input('filter string : ')
    v_sniff = VoidSniff(filter)
    v_sniff.run()
