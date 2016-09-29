import time
from scapy.all import *
from openflow_scenario import Openflow_scenario


class South_spoofing_scenario(Openflow_scenario):

    def __init__(self, sniff_thread, tcp_handshake):
        Openflow_scenario.__init__(self, sniff_thread, tcp_handshake)

    def launch(self):
        tmp = self.read_blocking()
        if len(tmp)>1:
            print("Warning : strange answering behavior (more than a SYN ACK received)")

        try:
            self.tcp_handshake.analyse_state_and_answer(tmp[0])
            self.tcp_handshake.send_data(OFPTHello(),tmp[0])

            self.counter = 0
            to_send = []
            while self.counter < 10:
                to_send.extend(self.react_to(self.read_blocking()))
                if len(to_send)>0:
                    self.tcp_handshake.send_data(to_send[0],self.last)
                    del to_send[0]
        except Exception,e:
            print("Exception raised with "+str(e))
            self.end()
            exit()

        self.end()
