#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import struct

from time import sleep
from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, XByteField, PacketListField, FieldLenField, Raw, Ether, IP, UDP, sendp, get_if_hwaddr, sniff


class InBandNetworkTelemetry(Packet):
    fields_desc = [ BitField("switchID_t", 0, 8),
                    BitField("priority", 0, 3),
                    BitField("qid", 0, 5),
                    BitField("enq_qdepth0",0,32),
                    BitField("enq_qdepth1",0,32),
                    BitField("totalLen",0,16)
                  ]
    def extract_padding(self, p):
                return "", p

class nodeCount(Packet):
  name = "nodeCount"
  fields_desc = [ ShortField("count", 0), ShortField("priority", 0),
                  PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt:(pkt.count*1))]

def main():

    addr = socket.gethostbyname(sys.argv[1])
    #iface = 'enp0s8'
    #tive q mudar
    iface = 'eth0' #pega o endereco mac dessa
    bind_layers(IP, nodeCount, proto = 253)
    #i = 0
    while True:
        #sending just to port qid0
        print("oie")
        print(iface)
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
            dst=addr, proto=253) / nodeCount(count = 0,priority = 0,INT=[])
        sendp(pkt, iface=iface)
        pkt.show2()
        #if i == 0:
            #i = 1
        #else:
            #i = 0
             #pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
             #dst=addr, proto=253) / nodeCount(count = 0, priority = 1, INT=[])
        #sendp(pkt,iface=iface)
    #pkt.show2()
        sleep(0.2)

    #sendp(pkt, iface=iface)
    #pkt.show2()

    #while True:
        #sendp(pkt, iface=iface)
        #pkt.show2()
        #sleep(0.2)

if __name__ == '__main__':
    main()
