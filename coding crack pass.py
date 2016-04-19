#!/usr/bin/python 
# hash-spit.py v1.2 
#                       ,              . 
#                 _.._ -+-*  * _. __ _.;_/ _ ._ _ 
#                (_][ ) | |  |(_]_) (_]| \(_)[ | ) 
#                          ._| 
#   .      .      _,   .            .              .       _,   . 
#  _| _.._.;_/ _.|.|  _| _         _| _ ._ ._. _  _| _. _.|.|  _| _ 
# (_](_][  | \(_.|_| (_](/,  and  (_](/,[_)[  (/,(_](_](_.|_| (_](/, 
#                                      | 
# hash bruteforcer (use string generator) 
# (md5, sha1, sha224, sha256, sha384, sha512) 
# 
# [Crochemore-Perrin algorithm] 
# bidirection generate string ex: 
# [0,1,2,3,4,5,6,7,8,9] 
# ---------> <--------- 
# start    end    start
# 
# this technique using to increase the probability and effectiveness 
# discover string searching. 
# 
# Author: 5ynL0rd 
# thanks to community: antijasakom.org, darkc0de.com & depredac0de.net 
# thanks to person: d3hydr8, gat3w4y, shamus, cyberchrome, renzo, 
#                   pyfla, si_pemula, g4pt3k, acayz, tr4c3r, dbuqr, 
#                   boys_rvn1609. 
#                                                          03 March 2010 
#------------------------------------------------------------------------ 

import string, os, time, sys, hashlib 
from itertools import product 

def banner(): 
 if os.name == "posix": 
  os.system("clear") 
 else: 
  os.system("cls") 
 header = ''' 
    ___________ 
   |.---------.| 
   ||         || 
   ||HASH-SPIT||     hash-spit.py v1.2 
   ||         ||     `````````````````` 
   |'---------'|     hash bruteforcer using string generator 
    `)__ ____('      (md5,sha1,sha224,sha256,sha384,sha512) 
    [=== -- o ]--. 
  __'---------'__ \       http://5ynl0rd.depredac0de.net 
 [::::::::::: :::] ) 
 `""'"""""'""""`/T\\ 
                \\_/                           Author: 5ynL0rd 
+-------------------------------------------------------------+\n''' 
 for i in header: 
  print "\b%s"%i, 
  sys.stdout.flush() 
  time.sleep(0.005) 

def synL0rd_perm(s,n): 
 x = (s,)*n 
 return product(*x) 

def format(): 
 print '''[+] Select generator: 
    0) a-z (abcdefghijklmnopqrstuvwxyz) 
    1) 0-9 (0123456789) 
    2) A-Z (ABCDEFGHIJKLMNOPQRSTUVWXYZ) 
    3) !-~ (!"#$%&\\\'()*+,-./:;<=>?@[\\\\]^_`{|}~) 
    4) a-z and 0-9 
    5) a-z and A-Z 
    6) a-z and !-~ 
    7) a-z and A-Z and 0-9 
    8) a-z and A-Z and !-~ 
    9) all''' 

if "__main__" == __name__: 
 banner() 
 lengthmin2 = 0 
 format() 
 try: 
  gen = input("    choose number options [1,2,..10]: ") 
 except: 
  print "[-] Error input!" 
  sys.exit(1) 
 else: 
  if gen > 9 or gen < 0: 
   print "[-] Error input!" 
   sys.exit(1) 
 lengthmin = input("[+] length min: ")
 lengthmax = input("[+] length max: ") 
 if lengthmin > lengthmax: 
  print "[-] Error input!" 
  sys.exit(1) 
 cipher = raw_input("[+] insert hash: ")
 cipher = cipher.lower() 
 if len(cipher) == 32: 
  hashtype = "MD5 HASH" 
 if len(cipher) == 40: 
  hashtype = "SHA1 HASH" 
 if len(cipher) == 56: 
  hashtype = "SHA224 HASH" 
 if len(cipher) == 64: 
  hashtype = "SHA256 HASH" 
 if len(cipher) == 96: 
  hashtype = "SHA384 HASH" 
 if len(cipher) == 128: 
  hashtype = "SHA512 HASH" 
 num0 = list(string.ascii_lowercase) 
 num1 = list(string.digits) 
 num2 = list(string.ascii_uppercase) 
 num3 = list(string.punctuation) 
 num4 = num0+num1 
 num5 = num0+num2 
 num6 = num0+num3 
 num7 = num0+num2+num1 
 num8 = num0+num2+num3 
 full = num0+num2+num1+num3 
 listnum = [num0,num1,num2,num3,num4,num5,num6,num7,num8,full] 
 print "[o] CRACKING %s! Please wait...\n"%hashtype 
 while lengthmin <= lengthmax:
  found = False
  ch3cksum = synL0rd_perm(listnum[gen],lengthmin)
  cent = listnum[gen][len(listnum[gen])/2]*lengthmin
  listnum[gen].reverse()
  gat3w4y = synL0rd_perm(listnum[gen],lengthmin)
  print "\r", 
  while found == False: 
   resgen1 = string.join(gat3w4y.next(),"") 
   resgen2 = string.join(ch3cksum.next(),"")
   if len(cipher) == 32: 
    spit1 = hashlib.md5(resgen1).hexdigest() 
    spit2 = hashlib.md5(resgen2).hexdigest() 
   if len(cipher) == 40: 
    spit1 = hashlib.sha1(resgen1).hexdigest() 
    spit2 = hashlib.sha1(resgen2).hexdigest() 
   if len(cipher) == 56: 
    spit1 = hashlib.sha224(resgen1).hexdigest() 
    spit2 = hashlib.sha224(resgen2).hexdigest() 
   if len(cipher) == 64: 
    spit1 = hashlib.sha256(resgen1).hexdigest() 
    spit2 = hashlib.sha256(resgen2).hexdigest() 
   if len(cipher) == 96: 
    spit1 = hashlib.sha384(resgen1).hexdigest() 
    spit2 = hashlib.sha384(resgen2).hexdigest() 
   if len(cipher) == 128: 
    spit1 = hashlib.sha512(resgen1).hexdigest() 
    spit2 = hashlib.sha512(resgen2).hexdigest() 
   print "\r    %s | %s"%(resgen1,resgen2), 
   sys.stdout.flush
   if cipher == spit1: 
    print "\n\n[+] PASSWORD CRACKED! = %s\n"%resgen1 
    found = True 
    sys.exit(0) 
   if cipher == spit2: 
    print "\n\n[+] PASSWORD CRACKED! = %s\n"%resgen2 
    found = True 
    sys.exit(0)
   if resgen1 == cent:
    break
  lengthmin += 1

 print "\n\n[-] PASSWORD NOT FOUND... Try again later\n"
