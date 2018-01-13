#RAW_SOCKET
import socket
import sys
import struct
import random
import time
import os
import time
import re
from urlparse import urlparse
# Flush IPTABLES to clear previous retransmissions
os.system('iptables -F')
os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
# Retrieving the source IP
try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',0))
        IP = s.getsockname()[0]

except socket.error , er:
        print "ERROR SOCKET :", er[1]
        sys.exit()
# DESTINATION PORT
port = 80
url = sys.argv[1]
if "http://" not in url:
    url = "http://" + url
host = urlparse(url)
hostname = host[1]
#print hostname
path = host[2]
#print path
mainfile = path.split('/')[-1:]
if path == '' or path[-1:] == "/":
    file_name = 'index.html'
else:
    file_name = mainfile[0]
hostip = socket.gethostbyname(hostname)
#print hostip
#print IP
#CLASS FOR CREATING THE PACKET BOTH TCP AND IP
class CreatePacket():

        def __init__(self, data=''):
                self.srcip = socket.inet_aton(IP)
                self.destip = socket.inet_aton(hostip)
                self.src_port = random.randint(49151, 65535)
                self.des_port = 80
                self.seq_no = random.randint(1, 4294967296)
                self.ack_no = 0
                self.offset = 5
                self.cwr = 0
                self.ece = 0
                self.urg = 0
                self.ack = 0
                self.push = 0
                self.reset = 0
                self.syn = 0
                self.fin = 0
                self.window = 65000
                self.checksum = 0
                self.urgp = 0
                self.data = 0

                if len(data) % 2 == 1:
                        data += "0"

                self.payload = data
        #CHECKSUM
        def tcp_checksum(self, msg):

                s = 0
                for i in range(0, len(msg), 2):
                        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
                        s = s + w
                s = (s>>16) + (s & 0xffff);
                s = s + (s >> 16);
                s = ~s & 0xffff
                return s

        def ip_header(self):
                ver = 4
                ihl = 5
                tos = 0
                tl = 0
                id = 55555
                flags = 0
                offset = 0
                ttl = 255
                protocol = socket.IPPROTO_TCP
                chksum = 0
                self.srcip = socket.inet_aton(IP)
                self.destip = socket.inet_aton(hostip)
                ver_ihl = (ver << 4) + ihl
                flags_offset = (flags << 13) + offset
                ip_head = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tl, id, flags_offset, ttl, protocol, chksum, self.srcip, self.destip)

                return ip_head

        def tcp_header(self):
                self.src_port
                self.des_port
                self.seq_no
                self.ack_no
                self.offset
                offset_res = (self.offset << 4) + 0
                self.cwr
                self.ece
                self.urg
                self.ack
                self.push
                self.reset
                self.syn
                self.fin
                flags = self.fin + (self.syn << 1) + (self.reset << 2) + (self.push << 3) + (self.ack << 4) + (self.urg << 5) + (self.ece << 6) + (self.cwr << 7)
                self.window
                self.checksum
                self.urgp
                tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.des_port, self.seq_no, self.ack_no, offset_res, flags, self.window, self.checksum, self.urgp)

        #PSEUDO header
                s_ip = socket.inet_aton(IP)
                d_ip = socket.inet_aton(hostip)
                placeholder = 0
                protocol = socket.IPPROTO_TCP
                total_length = len(tcp_header) + len(self.payload)
                pseudo1 = struct.pack("!4s4sBBH", s_ip, d_ip, placeholder, protocol, total_length)
                pseudo = pseudo1 + tcp_header + self.payload
                tcp_chcksum = self.tcp_checksum(pseudo)
                tcp_header = struct.pack("!HHLLBBH", self.src_port, self.des_port, self.seq_no, self.ack_no, offset_res, flags, self.window) + struct.pack('H', tcp_chcksum) + struct.pack('!H', sel$
                return tcp_header
        #COMBINING BOTH TCP AND IP HEADER
        def stack(self):
                ip_packet = self.ip_header()
                tcp_packet = self.tcp_header()

                stack = ip_packet + tcp_packet + self.payload
                return stack
        #RECEIVE PACKET
class ParsePacket():

                def __init__(self, packet):
                        self.packet = packet[0]
                        self.s_port = 0
                        self.d_port = 0
                        self.seq_no = 0
                        self.ack_no = 0
                        self.doff_res = 0
                        self.flags = 0
                        self.fin = 0
                        self.syn = 0
                        self.rst = 0
                        self.psh = 0
                        self.ack = 0
                        self.urg = 0
                        self.window = 0
                        self.checksum = 0
                        self.urg_port = 0
                        self.header_size = 0
                        self.data_size = 0
                        self.data = 0
                        self.ip_header = 0
                #TAKING OUT THE IP HEADER
                def parseip(self):

                        self.ip_header = self.packet[0:20]
                        ip_h = struct.unpack('!BBHHHBBH4s4s', self.ip_header)


                        ip_ver_ihl = ip_h[0]
                        ip_ver = ip_ver_ihl >> 4
                        ihl = ip_ver_ihl & 0xF

                        iph_length = ihl * 4

                        ttl = ip_h[5]
                        protocol = ip_h[6]
                        s_ip = socket.inet_ntoa(ip_h[8])
                        d_ip = socket.inet_ntoa(ip_h[9])

                        tcp_header = self.packet[20:40]

                        tcp_h = struct.unpack('!HHLLBBHHH', tcp_header)
                        #print tcp_h
                        self.s_port = tcp_h[0]
                        self.d_port = tcp_h[1]
                        self.seq_no = tcp_h[2]
                        self.ack_no = tcp_h[3]
                        self.doff_res = tcp_h[4]
                        self.flags = tcp_h[5]
                        self.tcp_length = self.doff_res >> 4
                        h_size = iph_length + self.tcp_length * 4
                        self.data_size = len(self.packet) - h_size

                        self.data = self.packet[h_size:]
                #SOCKETS
class RawConnect():

                def __init__(self):
                        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                        self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        self.dst_ip = hostip
                        #print hostip
                def send_syn(self):
                        syn = CreatePacket()
                        syn.syn = 1
                        #print "sYN"
                        #print syn.src_port
                        #print syn.des_port
                        #print syn.seq_no
                        #print syn.ack_no

                        self.ssocket.sendto(syn.stack(), (self.dst_ip, 0))

                def recv(self):
                        packet = self.rsocket.recvfrom(65535)
                        parse_pack = ParsePacket(packet)

                        parse_pack.parseip()

                def send_ack(self, recv_data, d_port, ack_no, seq_no):
                        ack = CreatePacket()
                        ack.src_port = d_port
                        ack.ack = 1
                        ack.push = 0
                        ack.seq_no = ack_no
                        ack.ack_no = seq_no + len(recv_data)
                        #print "sendACK"
                        #print ack.seq_no
                        #print ack.ack_no
                        self.ssocket.sendto(ack.stack(), (self.dst_ip, 0))

                def packet_drop(self):
                        global ssthresh, congestionwnd
                        ssthresh = 1000
                        ssthresh = ssthresh/2
                        congestionwnd = 1

                def congestion_avoidance(self):
                        global congestionwnd
                        congestionwnd = congestionwnd / 2
                        congestionwnd = congestionwnd + 1/congestionwnd

                def send_fin(self, recv_data, d_port, ack_no, seq_no):
                        fin = CreatePacket()
                        fin.src_port = d_port
                        fin.ack = 1
                        fin.push = 0
                        fin.fin = 1
                        fin.seq_no = ack_no
                        fin.ack_no = seq_no + len(recv_data)
                        self.ssocket.sendto(fin.stack(), (self.dst_ip, 0))

                def handshake(self):
                        handshake = CreatePacket()
                        recv = RawConnect()
                        packet = recv.rsocket.recvfrom(65535)
                        parse_pack = ParsePacket(packet)
                        parse_pack.parseip()
                        handshake.send_ack(parse_pack.ack_no, parse_pack.seq_no)

                def send_data(self, d_port, data, ack_no, seq_no):
                        send = CreatePacket(data)
                        send.src_port = d_port
                        send.push = 1
                        send.ack = 1
                        send.seq_no = ack_no
                        send.ack_no = seq_no
                        #print "send Data"
                        #print len(data)
                        #print send.seq_no
                        #print send.ack_no
                        #print len(send.payload)
                        self.ssocket.sendto(send.stack(), (self.dst_ip, 0))
#HANDSHAKING CODE
dict_seq = {}
handshake = RawConnect()
handshake.send_syn()
recv = RawConnect()
packet = handshake.rsocket.recvfrom(65535)
parse_pack = ParsePacket(packet)
parse_pack.parseip()
#print "SYNACK"
#print parse_pack.d_port
#print parse_pack.seq_no
#print parse_pack.ack_no
#print parse_pack.data
#print len(parse_pack.data)
handshake.send_ack(parse_pack.data, parse_pack.d_port, parse_pack.ack_no, parse_pack.seq_no + 1)

#GET HTTP
data = ''
d1 = "GET "+path+" HTTP/1.0\r\nHost: "+hostname+"\r\nConnection: keep-alive\r\n\r\n"
get_msg = d1
#print get_msg
handshake.send_data(parse_pack.d_port, get_msg, parse_pack.ack_no, parse_pack.seq_no + 1)
packet1 = handshake.rsocket.recvfrom(65535)
parse_pack1 = ParsePacket(packet1)
parse_pack1.parseip()
#print "RECEIVER ACK for GET"
packet2 = handshake.rsocket.recvfrom(65535)
parse_pack2 = ParsePacket(packet2)
parse_pack2.parseip()
#print parse_pack2.data
status = packet2[0][49:52]
#print status
#HANDLING STATUS CODE
if status != '200':
                if status == '301':
                        print("PAGE IS MOVED ")
                        sys.exit()
                if status == '400':
                        print("CHECK THE REQUEST")
                        sys.exit()

                if status == '404':
                        print('SORRY, PAGE NOT FOUND')
                        sys.exit()
                if status == '500':
                        print('INTERNAL SERVER ERROR')
                        sys.exit()
page263 = re.split(r'\r\n\r\n', parse_pack2.data)
#print page263
if "200 OK" not in page263:
    pass
else:
    dict_seq[parse_pack2.seq_no] = page263[1]
dict_seq[parse_pack2.seq_no] = page263[1]
#print "Data Received"
next_seq_no = parse_pack2.seq_no + len(parse_pack2.data)
i = 0
#ACK SENT
handshake.send_ack(parse_pack2.data, parse_pack2.d_port, parse_pack2.ack_no, parse_pack2.seq_no)
#CONGESTION CONTROL
global congestionwnd, ssthresh
congestionwnd = 1
ssthresh = 1000
Acktime = time.time()
# THIS IS POINT WE RECEIVE THE PACKETS AND SEND ACKNOWLEDGEMENTS

while True:
        #print "loop"
        i = i + 1
        #print i
        handshake1 = RawConnect()
        packet2 = handshake1.rsocket.recvfrom(65535)
        recvtime = time.time()
        parse_pack2 = ParsePacket(packet2)
        parse_pack2.parseip()
        #print parse_pack2.data
        #CODE TO HANDLE PACKET LOSS
        if recvtime - Acktime >= 60.0:
                difftime = recvtime - Acktime
                #print difftime
                handshake1 = RawConnect()
                handshake1.packet_drop()
                handshake1.send_ack(a1, a2, a3, a4)
                if difftime >= 180:
                        print "Nothing was received for 180 seconds"
                        sys.exit()
        if(next_seq_no == parse_pack2.seq_no):
                a1 = parse_pack2.data
                a2 = parse_pack2.d_port
                a3 = parse_pack2.ack_no
                congestionwnd += 1
                #print "congestion"
                #print congestionwnd
                if congestionwnd >= 1000:
                        handshake1 = RawConnect()
                        handshake1.congestion_avoidance()
                handshake1.send_ack(parse_pack2.data, parse_pack2.d_port, parse_pack2.ack_no, parse_pack2.seq_no)
                Acktime =  time.time()
                dict_seq[parse_pack2.seq_no] = parse_pack2.data
                next_seq_no = parse_pack2.seq_no + parse_pack2.data_size
                #print next_seq_no, "ack_sent"
                # CODE TO CHECK WHEN WE HAVE RECEIVED A FINACK
                if(parse_pack2.flags == 25):
                        packet2 = handshake1.rsocket.recvfrom(65535)
                        parse_pack2 = ParsePacket(packet2)
                        parse_pack2.parseip()
                        handshake1.send_fin(parse_pack2.data, parse_pack2.d_port, parse_pack2.ack_no, parse_pack2.seq_no)
                        #print "FINACKSENT"
                        page4 = ''
                        page4 += page4 + parse_pack2.data
                        #print page4
                        break
#REARRANGING THE PACKETS
page2 = ''
ordered_dict = sorted(dict_seq.keys())
for keys in ordered_dict:
        page2 += dict_seq[keys]
#print page2
handshake.rsocket.close()
handshake1.rsocket.close()
#CODE TO WRITE THE FILE
target = open(file_name, "wb")
target.write(page2)
#print target
#print b
target.close()
os.system('iptables -F')
sys.exit()



