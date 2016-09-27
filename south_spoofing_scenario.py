import time
from scapy.all import *


class South_spoofing_scenario:

    def __init__(self, sniff_thread, tcp_handshake):
        self.sniff_thread = sniff_thread
        self.tcp_handshake = tcp_handshake
        self.echo = False
        self.answer_features = False
        self.answer_config = False
        self.answer_barrier = False
        self.counter_dict = {'echo':0,'config':0,'features':0,'barrier':0}

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
            print(repr(p.lastlayer()))

            self.tcp_handshake.analyse_state_and_answer(p)
            self.last = p

            if p.haslayer(OFPTHello):
                self.counter += 1
            elif p.haslayer(OFPTFeaturesRequest):
                self.answer_features = True
                self.send_response()
                self.counter += 1
            elif p.haslayer(OFPTEchoRequest):
                self.echo = True
                self.send_response()
            elif p.haslayer(OFPTGetConfigRequest):
                self.answer_config = True
                self.send_response()
                self.counter += 1
            elif p.haslayer(OFPTBarrierRequest):
                self.answer_barrier = True
                self.send_response()

    def send_response(self):
        if self.echo:
            self.counter_dict['echo'] += 1
            self.echo = False
            print("ECHOO ")
            self.tcp_handshake.send_data(OFPTEchoReply(),self.last)
        elif self.answer_config:
            self.counter_dict['config'] += 1
            self.answer_config = False
            print("Answer config ")
            self.tcp_handshake.send_data(OFPTGetConfigReply(),self.last)
        elif self.answer_features:
            self.counter_dict['features'] += 1
            self.answer_features = False
            print("Answer features ")
            self.tcp_handshake.send_data(OFPTFeaturesReply(),self.last)
        elif self.answer_barrier:
            self.counter_dict['barrier'] += 1
            self.answer_barrier = False
            print("Answer barrier ")
            self.tcp_handshake.send_data(OFPTBarrierReply(),self.last)

    def launch(self):
        tmp = self.read_blocking()
        if len(tmp)>1:
            print("Warning : strange answering behavior (more than a SYN ACK received)")

        self.tcp_handshake.analyse_state_and_answer(tmp[0])
        self.tcp_handshake.send_data(OFPTHello(),tmp[0])

        self.counter = 0
        while self.counter < 1:
            self.react_to(self.read_blocking())

        while self.counter < 10:
            self.react_to(self.read_blocking())

        self.end()

    def end(self):
        self.tcp_handshake.send_fin()
        while not self.tcp_handshake.communication_ended():
            tmp = self.read_blocking()
            for i in tmp:
                self.tcp_handshake.analyse_state_and_answer(i)
