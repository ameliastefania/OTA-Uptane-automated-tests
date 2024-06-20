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
    print("Source ip: ", ip.src)
    print("Destination ip: ", ip.dst)
    
    # find the location in the tcpPayload for TLS ECDHE ECDSA WITH AES 256 GCM SHA384 ciphersuite
    # we know for a fact that this cipersuite is represented in c0 2c bytes (check with wireshark)
    # we know for a fact that the first byte from the handshake is 0x16 0x03 (meaning the TLS version; consult RFC tls documentation for more details)
    # https://datatracker.ietf.org/doc/html/rfc5246#page-37
      
    if tcpPayload[0] == 0x16 and tcpPayload[1] == 0x03 and tcpPayload[84] == 0xc0 and tcpPayload[85] == 0x2c:
      #print(tcpPayload)
      #print(pkt.get_payload()) 
     
      print("Packet that should be droped")
      
      pkt.drop()
      #pkt.accept()
    else:
      pkt.accept()

print("Binding to NFQUEUE", nfQueueID)
nfqueue = NetfilterQueue()
nfqueue.bind(nfQueueID, packetReceived, maxPacketsToStore) # binds to queue 0, use handler "packetReceived()"
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('Listener killed.')

nfqueue.unbind()