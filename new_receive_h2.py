#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from time import sleep
from scapy.all import Packet, bind_layers, XByteField, FieldLenField, BitField, ShortField, IntField, PacketListField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff


class InBandNetworkTelemetry(Packet):
    fields_desc = [ BitField("switchID_t", 0, 8),
                    BitField("priority", 0, 3),
                    BitField("qid", 0, 5),
                    BitField("enq_qdepth0", 0, 32),
                    BitField("enq_qdepth1", 0, 32),
                    BitField("totalLen",0,16)
                  ]
    """any thing after this packet is extracted is padding"""
    def extract_padding(self, p):
                return "", p

class nodeCount(Packet):
  name = "nodeCount"
  fields_desc = [ ShortField("count", 0), ShortField("priority", 0),
                  PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt:(pkt.count*1))]

def getFields(pkt):
  fields_names = []
  fields = {}
  
  for lengthInt in range(len(pkt[nodeCount].INT)):
    field_names = [field.name for field in pkt[nodeCount].INT[lengthInt].fields_desc]
    fields[lengthInt] = {field_name: getattr(pkt[nodeCount].INT[lengthInt], field_name) for field_name in field_names}
  #print('fields retornado = ' + str(fields))
  return fields

def logInt(fields_value):
  line_values_temp = []
  for lenFieldsValue in range(len(fields_value)):
    sep = ','
    temp1 = sep.join(map(str,list(fields_value[lenFieldsValue].values())))
    line_values_temp.append(temp1)

  sep = ','
  line_values = sep.join(map(str,list(line_values_temp)))
  
  print('escrevendo' + str(line_values))
  with open('logs/log_INT.txt','a+') as file:
    file.write(line_values + '\n')

def handle_pkt(pkt):
  fields_value = getFields(pkt)
  logInt(fields_value)
  pkt.show2()
  
def main():
  #new, output file
  header_fileLog = ['switchID_t', 'priority', 'qid', 'enq_qdepth0', 'enq_qdepth1', 'totalLen', 'switchID_t', 'priority', 'qid', 'enq_qdepth0', 'enq_qdepth1', 'totalLen']
  header_fileLogAux = [f'{item}' for item in header_fileLog]
  header = ", ".join(header_fileLogAux)
  #print(header)
  
  with open('logs/log_INT.txt','w+') as file:
      file.write(str(header) + '\n')
  #mudei
  #iface = 'enp0s8'
  iface = 'eth0'
  bind_layers(IP, nodeCount, proto = 253)
  sniff(filter = "ip proto 253", iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

