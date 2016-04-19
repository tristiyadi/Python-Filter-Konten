#!/usr/bin/python

# simple IDS dan Filter Konten Internet
# raw_socket module (harus dirunning dengan sudo atau user=root karena raw socket hanya bisa dijalankan dengan hak akses root)
#
# Coder By : Eko Tristiyadi
# Algorthma saya menggunakan string matching untuk match text filter_
# string pada ip header data = packet
# if re.search(filter_string,packet): lakukan pencarian
#-----------------------------------------------

# Selanjutnya adalah handling block ip address dan parsing ip address source ke firewall
# Untuk firewall program ini menggunakan iptables

from termcolor import colored
import os
import socket
import sys
from struct import *
import string
import re  
import time
import json
import MySQLdb
from datetime import datetime

colorred = "\033[01;31m{0}\033[00m"
colorgrn = "\033[1;32m{0}\033[00m"
colorblu = "\033[1;34m{0}\033[00m"

os.system('clear')
if not os.geteuid()==0:
    print colorred.format("\nHanya root yang bisa menjalankan script ini\n")
    sys.exit(0)

def logo():
    print colorred.format("-######################################################################-")
    print colorgrn.format("- FILTER PAKET INTERNET MENGGUNAKAN PYTHON PAKAI FILTER STRING SOCKET  -")
    print colorblu.format("-  mail me: ekotristiyadi@if.uai.ac.id      [ IF 12 UAI ] Version-1.0  -")
    print colorred.format("-######################################################################-\n")

def pakets(setup,filter_konten):
    # untuk socket stream
    # fungsi untuk menerima data, kita set jumlah byte yg diperbolehkan
    paket = setup.recvfrom(65535)
    #packet string from tuple
    paket = paket[0]
    #take first 20 characters for the ip headerdef paket(setup,filter_konten):
    # untuk socket stream
    # fungsi untuk menerima data, kita set jumlah byte yg diperbolehkan
    paket = setup.recvfrom(65535)
    #packet string from tuple
    paket = paket[0]
    #take first 20 characters for the ip header
    
    ip_header = paket[0:20]
    # now unpack them for ip header
    # Extract the 20 bytes IP header, ignoring the IP options
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    #iph = unpack('>HHHHBBBBa2a2', ip_header)    
	
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
    
    ttl = iph[5]
    protocol = iph[6]    
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
	
    tcp_header = paket[iph_length:iph_length+20]
    # now unpack them for tcp header
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
	
    tgl = datetime.today()
    log_tgl = str(tgl)
    try:
        #filter_konten = open('data_filter_konten.json','r').write()
        log_payload_filter = open("payload_detail"+log_tgl+".log", "a+") # mode +a = bisa di write seperti mode w

    except:
        print colorred.format('File Tidak Ditemukan')
	
    try:
	filter_konten = open('data_filter_konten.json','r').read()
	#pakai findall ??
        if re.search(filter_konten,paket):
            print colorred.format('==============================================================================')
            print colorgrn.format('Alert Ditemukan Filter Konten : ' + filter_konten)
            print colorgrn.format('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
            print colorgrn.format('Source Port : ' + str(source_port) + ' Destination Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
            print colorblu.format('Waktu Alert : '  + str(datetime.now()))
            print colorred.format('==============================================================================')	  
              
	    h_size = iph_length + tcph_length * 4
            data_size = len(paket) - h_size
            #get data from the packet
            data = paket[h_size:]
            print 'Data Payload : ' + data
            print
            print colorred.format('==============================================================================')
	    print '\n\n\n'
	 
            #ip_s = socket.getfqdn(s_addr)
	    #ip_s = socket.gethostbyname_ex(s_addr)
	    ip_s = socket.gethostbyname(s_addr)
            
            # Simpan Data Alert ke payload_detail.log
            log_payload_filter.write('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')	  
            log_payload_filter.write('Filter Konten : '+filter_konten+'\nDari IP Tujuan : '+str(d_addr)+' Akan Ke : ['+str(ip_s)+'] Pada Waktu : '+str(datetime.now())+'\n')
            log_payload_filter.close()

            data_js = [{'IP Address Sumber': str(ip_s),
                        'IP Address Tujuan': str(d_addr),
                        'Port IP Sumber': str(source_port),
                        'Port IP Tujuan': str(dest_port),
                        'Waktu Akses': str(datetime.now()),
            }]
            data_js = json.dumps(data_js)

            try:
                data_sbl = open('data_trafik.json', 'r').read()
            except Exception, err:
                open('data_trafik.json', 'w').write(data_js)
            else:
                data_sbl = json.loads(data_sbl)
                data_js = json.loads(data_js)
                data_js = data_sbl + data_js
                open('data_trafik.json', 'w').write(json.dumps(data_js))

            try:
                redirect_data = open('blacklist.json', 'r').read()
            except Exception, err:
                redirect_data = [] #buat kumpulin jadi 1 biar gak redundan di array
            else:
                redirect_data = json.loads(redirect_data)

            data_from_json = open('data_trafik.json', 'r').read()
            data_from_json = json.loads(data_from_json)

            if {'IP Address Sumber': str(ip_s)} not in redirect_data:
                data_b = json.dumps([{'IP Address Sumber': str(ip_s)}])
                try:
                    data_b_sbl = open('blacklist.json', 'r').read()
                except Exception, err:
                    pass
                else:
                    data_b = json.loads(data_b_sbl) + json.loads(data_b)
                    data_b = json.dumps(data_b)
                open('blacklist.json', 'w').write(data_b)
                # Untuk Membelokkan paket ke port komputer itu sendiri
		os.system('/sbin/iptables -A OUTPUT -s %s -j DROP' % str(ip_s))
		os.system('/sbin/iptables -A FORWARD -s %s -j DROP' % str(ip_s))
		os.system('/sbin/iptables -A INPUT -s %s -j DROP' % str(ip_s))

                #os.system('/sbin/iptables -t nat -A PREROUTING -i eth0 -s %s -p tcp --dport %s -j REDIRECT --to-port 80' % (str(ip_s),str(dest_port)) )
                #os.system('/sbin/iptables -t nat -A PREROUTING -i eth0 -s %s -p tcp --dport %s -j REDIRECT --to-port 80' % (str(ip_s),str(dest_port)) )
                # os.system('/sbin/iptables -t NAT -F')
            #os.remove('data_trafik.json')
	    db = MySQLdb.connect(unix_socket="/opt/lampp/var/mysql/mysql.sock",user="root",passwd="root",db="konten_filter")
	    cursor=db.cursor()
	    sql="INSERT INTO blacklist_konten(ip_sumber, ip_tujuan, port_sumber, port_tujuan) VALUES ('%s', '%s', '%s', '%s')" % (str(ip_s), str(d_addr), str(source_port), str(dest_port))
	    try:
		cursor.execute(sql)
		db.commit()
	    except:
		db.rollback()
	    db.close()

            
    except Exception ,err:
        print [err]
    
	
def paket(setup,filter_konten):
    # untuk socket stream
    # fungsi untuk menerima data, kita set jumlah byte yg diperbolehkan 
    paket = setup.recvfrom(65535) 
    #packet string from tuple
    paket = paket[0] 
    #take first 20 characters for the ip header
    ip_header = paket[0:20]
    # now unpack them for ip header
    # Extract the 20 bytes IP header, ignoring the IP options
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    #iph = unpack('>HHHHBBBBa2a2', ip_header)    
	
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
    
    ttl = iph[5]
    protocol = iph[6]    
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
	
    tcp_header = paket[iph_length:iph_length+20]
    # now unpack them for tcp header
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
	
    #tgl = datetime.today()
    #log_tgl = str(tgl)
    try:
        #log_json = open('data_trafik.json','a+')
        log_payload_filter = open('payload_detail.log','a+')

    except:
        print colorred.format('File Tidak Ditemukan')
	
    try:
        if re.search(filter_konten,paket):
            print colorred.format('==============================================================================')
            print colorgrn.format('Alert Ditemukan Filter Konten : ' + filter_konten)
            print colorgrn.format('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
            print colorgrn.format('Source Port : ' + str(source_port) + ' Destination Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
            print colorblu.format('Waktu Alert : '  + str(datetime.now()))
            print colorred.format('==============================================================================')	  
              
	    h_size = iph_length + tcph_length * 4
            data_size = len(paket) - h_size
            #get data from the packet
            data = paket[h_size:]
            print 'Data Payload : ' + data
            print
            print colorred.format('==============================================================================')
	    print '\n\n\n'
	 
            #ip_s = socket.getfqdn(s_addr)
	    #ip_s = socket.gethostbyname_ex(s_addr)
	    ip_s = socket.gethostbyname(s_addr)
            
            # Simpan Data Alert ke payload_detail.log
            log_payload_filter.write('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')	  
            log_payload_filter.write('Filter Konten : '+filter_konten+'\nDari IP Tujuan : '+str(d_addr)+' Akan Ke : ['+str(ip_s)+'] Pada Waktu : '+str(datetime.now())+'\n')
            log_payload_filter.close()

            data_js = [{'IP Address Sumber': str(ip_s),
                        'IP Address Tujuan': str(d_addr),
                        'Port IP Sumber': str(source_port),
                        'Port IP Tujuan': str(dest_port),
                        'Waktu Akses': str(datetime.now()),
            }]
            data_js = json.dumps(data_js)

            try:
                data_sbl = open('data_trafik.json', 'r').read()
            except Exception, err:
                open('data_trafik.json', 'w').write(data_js)
            else:
                data_sbl = json.loads(data_sbl)
                data_js = json.loads(data_js)
                data_js = data_sbl+data_js
	        open('data_trafik.json', 'w').write(json.dumps(data_js))

            try:
                redirect_data = open('blacklist.json', 'r').read()
            except Exception, err:
                redirect_data = [] #buat kumpulin jadi 1 biar gak redundan di array
            else:
                redirect_data = json.loads(redirect_data)

            data_from_json = open('data_trafik.json', 'r').read()
            data_from_json = json.loads(data_from_json)

            if {'IP Address Sumber': str(ip_s)} not in redirect_data:
                data_b = json.dumps([{'IP Address Sumber': str(ip_s)}])
                try:
                    data_b_sbl = open('blacklist.json', 'r').read()
                except Exception, err:
                    pass
                else:
                    data_b = json.loads(data_b_sbl) + json.loads(data_b)
                    data_b = json.dumps(data_b)
                open('blacklist.json', 'w').write(data_b)
                # Untuk Membelokkan paket ke port komputer itu sendiri
		os.system('/sbin/iptables -A OUTPUT -s %s -j DROP' % str(ip_s))
		os.system('/sbin/iptables -A FORWARD -s %s -j DROP' % str(ip_s))
		os.system('/sbin/iptables -A INPUT -s %s -j DROP' % str(ip_s))

                #os.system('/sbin/iptables -t nat -A PREROUTING -i eth0 -s %s -p tcp --dport %s -j REDIRECT --to-port 80' % (str(ip_s),str(dest_port)) )
                #os.system('/sbin/iptables -t nat -A PREROUTING -i eth0 -s %s -p tcp --dport %s -j REDIRECT --to-port 80' % (str(ip_s),str(dest_port)) )
                # os.system('/sbin/iptables -t NAT -F')
            #os.remove('data_trafik.json')
            db = MySQLdb.connect(unix_socket="/opt/lampp/var/mysql/mysql.sock",user="root",passwd="root",db="konten_filter")
            cursor=db.cursor()
            sql="INSERT INTO blacklist_konten(ip_sumber, ip_tujuan, port_sumber, port_tujuan) VALUES ('%s', '%s', '%s', '%s')" % (str(ip_s), str(d_addr), str(source_port), str(dest_port))
	    try:
                cursor.execute(sql)
	        db.commit()
            except:
                db.rollback()
            db.close()
            
    except Exception ,err:
        print [err]
       
def paket_a():
    #socket AF_INET(addres family ipv 4) dan STREAM (TCP protocol)
    setup = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print colorred.format('=============================================')
    print colorgrn.format('||     Program Konten Filter Internet      ||')
    filter_konten = raw_input('Input 1 Kata untuk Filter Konten Internet : ')
    while True:
       try:
         paket(setup,filter_konten)
	 
       except KeyboardInterrupt:
	 print colorred.format('\n++++++++++++++++++++++++++++++++++++++++++++++++++')
	 print colorblu.format('\n+     [!] Maaf Program dipaksa berhenti...       +')
	 print colorblu.format("\n+   Terimakasih Sudah Memfilter Konten Internet  +")
	 print colorred.format('++++++++++++++++++++++++++++++++++++++++++++++++++++')
	 sys.exit()
       except Exception ,er:
         print er
         sys.exit()
         break

def paket_b():
    #socket AF_INET(addres family ipv 4) dan STREAM (TCP protocol)
    setup = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print colorred.format('=============================================')
    print colorgrn.format('||     Program Konten Filter Internet      ||')
    #filter_konten = raw_input('Input Kata Per Kata untuk Filter Konten Internet : ')

    filter_konten = list()
    kata = raw_input("Input Jumlah Kata yang akan difilter: ")
    print 'Silahkan Input Kata Yang Akan difilter: '
    for i in range(int(kata)):
	n = raw_input("Kata Filter Ke-"+str(i+1)+" : ")
	filter_konten.append(str(n))
    print 'Kata Difilter: ',filter_konten

    filter_konten = json.dumps(filter_konten)
    try:
	data = open('data_kata_filter.json','r').read()
    except Exception, Err:
	open('data_kata_filter.json','w').write(filter_konten)
    else:
	data = json.loads(data)
	filter_konten = json.loads(filter_konten)
	filter_konten = data+filter_konten
	open('data_kata_filter.json', 'w').write(json.dumps(filter_konten))


    lagi = raw_input('Apakah Anda Ingin Kata Diatas Untuk Difilter (y/n) : ')
    if lagi == 'y':
        
    	while True:
            try:
            	pakets(setup,filter_konten)

	    except KeyboardInterrupt:
        	print colorred.format('\n++++++++++++++++++++++++++++++++++++++++++++++++++')
            	print colorblu.format('\n+     [!] Maaf Program dipaksa berhenti...       +')
            	print colorblu.format("\n+   Terimakasih Sudah Memfilter Konten Internet  +")
            	print colorred.format('++++++++++++++++++++++++++++++++++++++++++++++++++++')
            	sys.exit()
            except Exception ,er:
            	print er
            	sys.exit()
           	break
    else:
	print colorred.format('Anda Tidak Memilih, Default Back To Menu Utama')
	dashboard()
    
def lihatjson():
    try:    
        lihat = open('alert_detail.json', 'r').read()
        
    except Exception, err:
        print err
        print colorgrn.format('Maaf File JSON Tidak Ditemukan')
        sys.exit(0)
    print '\n'    
    print colorgrn.format("1. Lihat Data JSON di Command Line")
    print colorgrn.format("2. Lihat Data JSON di Editor NANO")
    print colorgrn.format("3. Lihat Data JSON di Browser Firefox")
    print colorgrn.format("4. Kembali Ke Menu Awal")
    print colorgrn.format("5. Keluar Dari Program")

    pilih = input("\nSilahkan Pilih [1-5] ? ")
    try:
    	if pilih == 1:
            print colorgrn.format("++++++++++++++++++++++++++++++++")
            print colorgrn.format("Lihat Data JSON di Command Line")
            print lihat
	elif pilih == 2:
	    print colorgrn.format("++++++++++++++++++++++++++++++++")
	    print colorgrn.format("Lihat data JSON di Editor NANO")
	    os.system('nano blacklist.json')
        elif pilih == 3:
            print colorgrn.format("++++++++++++++++++++++++++++++++")
            print colorgrn.format("Lihat Data JSON di Browser Firefox")
	    os.system('rm /opt/lampp/htdocs/blacklist.json')
	    os.system('cp blacklist.json /opt/lampp/htdocs/')
            os.system('open firefox http://localhost/blacklist.php')
        elif pilih == 4:
            print colorgrn.format("++++++++++++++++++++++++++++++++")
            dashboard()
        elif pilih == 5:
    	    print '\n\n'
            print colorred.format("Byeeee !!!!!!")
            sys.exit()
        else:
     	    print colorred.format("[!] ** Angka "+str(pilih)+" Tidak Ada dalam Pilihan **\n")
            print colorred.format("[!] ** Silahkan Input Angka [1-5]")
            lihatjson()
    except Exception, er:
        print colorred.format("\n[!] ** Maaf, Anda Tidak Memilih Apapun...")
        print colorblu.format("[!] ** Silahkan Input Angka [1-4] **")
        lihatjson()
	  

def dashboard():
    print '\n'
    logo()
    print colorgrn.format("1. Input 1 Kata Untuk Filter Konten")
    print colorgrn.format("2. Input Kata Per Kata yang akan di Filter")
    print colorgrn.format("3. Lihat File IP Blacklist .JSON")
    print colorgrn.format("4. Keluar Dari Program")

    pilih = input("\nSilahkan Pilih [1-4] ? ")
    try:
    	if pilih == 1:
	    print colorgrn.format("Input 1 Kata Untuk Filter Konten")
            paket_a()
    	elif pilih == 2:
            print colorgrn.format("Input Kata Per Kata yang akan di Filter")
            #print colorgrn.format("Masih Progress")
            paket_b()
    	elif pilih == 3:
	    print '\n'
            print colorgrn.format("Lihat File IP Blacklist .JSON")
            lihatjson()
    	elif pilih == 4:
	    print colorred.format("\n\nByeeeeee !!!!\n")
	else:
	    os.system('clear') 
            print colorred.format("[!] ** Angka "+str(pilih)+" Tidak Ada dalam Pilihan **\n")
            print colorblu.format("[!] ** Silahkan Input Angka [1-4]")
	    dashboard()
    except Exception, er:
	print colorred.format("\n[!] ** Maaf, Anda Tidak Memilih Apapun...")
	print colorblu.format("[!] ** Silahkan Input Angka [1-4] **")
	dashboard()

if  __name__ == "__main__":
    os.system('clear')
    dashboard()
