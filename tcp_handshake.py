from scapy.all import *

import time

def date_to_str():
    return time.strftime("%H:%M:%S", time.gmtime(time.time()))


class TcpHandshake(object):

    def __init__(self, target):
        self.seq = 0
        self.ack = 0
        self.target = target
        self.dst = iter(Net(target[0])).next()
        self.dport = target[1]
        self.sport = random.randrange(0,2**16)
        self.l4 = IP(dst=target[0])/TCP(sport=self.sport, dport=self.dport, flags=0,
                                        seq=random.randrange(0,2**32))
        self.src = self.l4.src
        self.swin = self.l4[TCP].window
        self.dwin = 1

        self.end_send = False
        self.end_receive = False
        self.wait_for_final_ack = False

    def start(self):
        return self.send_syn()

    def send_simple(self, set_ack = True):
        if set_ack:
            self.l4[TCP].ack = self.ack
        else:
            self.l4[TCP].ack = 0
        self.l4[TCP].seq = self.seq
        send(self.l4, iface="vboxnet0")

    def send_syn(self):
        self.l4[TCP].flags = "S"
        self.send_simple(False)
        print("Syn sent at "+date_to_str())

    def send_synack_ack(self, pkt):
        self.l4[TCP].flags = "SA"
        self.send_simple()
        print("Syn Ack sent at "+date_to_str())

    def send_data(self, d, previous):
        self.l4[TCP].flags = "PA"
        payload_length = previous[IP].len-4*previous[IP].ihl-4*previous[TCP].dataofs
        self.seq = previous[TCP].ack
        self.ack = previous[TCP].seq + payload_length
        self.l4[TCP].ack = self.ack
        self.l4[TCP].seq = self.seq
        print("Sending data with seq "+str(self.seq))
        send(self.l4/d, iface="vboxnet0")

    def send_fin(self):
        self.end_send = True
        self.l4[TCP].flags = "F"
        self.send_simple()
        print("Fin sent at at "+date_to_str())

    def send_finack(self, pkt):
        self.end_send = True
        self.l4[TCP].flags = "FA"
        self.send_simple()
        print("Fin Ack sent at "+date_to_str())

    def send_ack(self, pkt):
        self.l4[TCP].flags = "A"
        self.send_simple()
        print("Ack sent with "+str(self.seq)+" at "+date_to_str())


    def analyse_state_and_answer(self, answer_pkt):
        if answer_pkt and answer_pkt.haslayer(IP) and answer_pkt.haslayer(TCP):
            payload_length = answer_pkt[IP].len-4*answer_pkt[IP].ihl-4*answer_pkt[TCP].dataofs
            self.seq = answer_pkt[TCP].ack
            self.ack = answer_pkt[TCP].seq + payload_length
            if answer_pkt[TCP].flags & 0x12 == 0x12:   # SYN+ACK
                print("Received Syn Ack")
                self.ack += 1
                self.send_ack(answer_pkt)
            elif answer_pkt[TCP].flags & 4 == 4:      # RST
                print("Received Rst")
                self.end_receive = True
                self.end_send = True
            elif answer_pkt[TCP].flags & 0x11 == 0x11: # FIN+ACK
                print("Received Fin Ack")
                self.ack += 1
                if not self.end_send:
                    self.send_finack(answer_pkt)       # close communication on other side too
                    self.wait_for_final_ack = True
                else:
                    self.send_ack(answer_pkt)
                    self.end_receive = True
                self.end_send = True
            elif answer_pkt[TCP].flags & 1 == 1:     # FIN
                print("Received Fin")
                self.ack += 1
                self.send_finack(answer_pkt)
                self.end_receive = True
            else:
                #self.ack += 1
                if answer_pkt[TCP].flags != 0x10:   #not ACK
                    print("Received Unknown")
                    self.send_ack(answer_pkt)
                else:
                    print("Received Ack")
                    if self.wait_for_final_ack:
                        self.end_receive = True

    def communication_ended(self):
        return self.end_send and self.end_receive
