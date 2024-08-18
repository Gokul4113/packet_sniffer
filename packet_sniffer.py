import socket
from scapy.all import *
from scapy.layers.l2 import Ether

socket_sniffer = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
interact = "eth0"
socket_sniffer.bind((interact,0))

try:
    while True:
        rawdata , addr = socket_sniffer.recvfrom(65535)
        packet = Ether(rawdata)
        print(packet.summary())


except KeyboardInterrupt:
       socket_sniffer.close()