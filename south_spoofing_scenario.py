import time
from scapy.all import *


class South_spoofing_scenario:

    def __init__(self, sniff_thread, tcp_handshake):
        self.sniff_thread = sniff_thread
        self.tcp_handshake = tcp_handshake

    def read_blocking(self):
        tmp = self.sniff_thread.get_packets()
        while len(tmp) == 0:
            time.sleep(0.1)
            tmp = self.sniff_thread.get_packets()
            if self.tcp_handshake.communication_ended():
                print("Communication Ended !")
                exit()
        return tmp

    def react_to(self, pkt):
        for p in pkt:
            print(repr(p))
            print(p.haslayer(OFPTHello))
            print(p.haslayer(OFPTEchoRequest))
            print(p.haslayer(OFPTFeaturesRequest))
            print(repr(p.lastlayer()))

            self.tcp_handshake.analyse_state_and_answer(p)
            self.last = p

    def launch(self):
        tmp = self.read_blocking()
        if len(tmp)>1:
            print("Warning : strange answering behavior (more than a SYN ACK received)")

        self.tcp_handshake.analyse_state_and_answer(tmp[0])
        self.tcp_handshake.send_data(OFPTHello(),tmp[0])

        self.counter = 0
        while self.counter < 2:
            self.react_to(self.read_blocking())
            self.counter += 1

        self.end()

    def end(self):
        while not self.tcp_handshake.communication_ended():
            self.tcp_handshake.send_finack(self.last)
            tmp = self.read_blocking()
            for i in tmp:
                self.tcp_handshake.analyse_state_and_answer(i)
