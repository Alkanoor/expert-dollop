import time
from scapy.all import *


class South_spoofing_scenario:

    def __init__(self, sniff_thread, tcp_handshake):
        self.sniff_thread = sniff_thread
        self.tcp_handshake = tcp_handshake
        self.echo = False

    def read_blocking(self):
        tmp = self.sniff_thread.get_packets()
        while len(tmp) == 0:
            time.sleep(0.1)
            tmp = self.sniff_thread.get_packets()
            if self.tcp_handshake.communication_ended():
                print("Communication Ended !")
                exit()
        self.last = tmp[-1]
        return tmp

    def react_to(self, pkt):
        for p in pkt:
            if p.haslayer(OFPTHello):
                self.counter += 1
            elif p.haslayer(OFPTFeaturesRequest):
                self.counter += 1
            elif p.haslayer(OFPTEchoRequest):
                self.echo = True

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
        while self.counter < 1:
            self.react_to(self.read_blocking())
            if self.echo:
                self.echo = False
                print("ECHOO ")
                self.tcp_handshake.send_data(OFPTEchoReply(),self.last)
                break

        self.tcp_handshake.send_data(OFPTFeaturesReply(),self.last)
        while self.counter < 10:
            self.react_to(self.read_blocking())
            if self.echo:
                self.echo = False
                print("ECHOOO ")
                self.tcp_handshake.send_data(OFPTEchoReply(),self.last)
                break

        self.end()

    def end(self):
        self.tcp_handshake.send_fin()
        while not self.tcp_handshake.communication_ended():
            tmp = self.read_blocking()
            for i in tmp:
                self.tcp_handshake.analyse_state_and_answer(i)
