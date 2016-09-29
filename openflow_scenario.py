import time
from scapy.all import *
from scenario import Scenario


class Openflow_scenario(Scenario):

    def __init__(self, sniff_thread, tcp_handshake):
        Scenario.__init__(self, sniff_thread, tcp_handshake)
        self.echo = False
        self.answer_features = False
        self.answer_config = False
        self.answer_barrier = False
        self.answer_stats = False
        self.counter_dict = {'echo':0,'config':0,'features':0,'barrier':0,'stats':0}

    def react_to(self, pkt):
        to_send = []
        for p in pkt:
            cur_payload = p[TCP].payload
            additional_pkts = [cur_payload]

            print(repr(cur_payload))
            if self.is_openflow(p):
                while cur_payload.len != len(cur_payload):
                    cur_payload = TCP.guess_payload_class(p[TCP],str(cur_payload.payload))(str(cur_payload.payload))
                    additional_pkts.append(cur_payload)
                    print(repr(cur_payload))

            print(str(len(additional_pkts))+" found !")

            self.tcp_handshake.analyse_state_and_answer(p)
            self.last = p

            for a in additional_pkts:
                b = self.analyse_and_send(a)
                if b is not None:
                    to_send.append(b)
        return to_send

    def is_openflow(self, p):
        for c in ofpt_cls:
            if p.haslayer(ofpt_cls[c]):
                return True
        for c in ofp_multipart_request_cls:
            if p.haslayer(ofp_multipart_request_cls[c]):
                return True
        for c in ofp_multipart_reply_cls:
            if p.haslayer(ofp_multipart_reply_cls[c]):
                return True
        for c in ofp_error_cls:
            if p.haslayer(ofp_error_cls[c]):
                return True
        return False

    def analyse_and_send(self, p):
        if p.haslayer(OFPTHello):
            self.counter += 1
        elif p.haslayer(OFPTFeaturesRequest):
            self.answer_features = True
            self.counter += 1
            return self.send_response()
        elif p.haslayer(OFPTEchoRequest):
            self.echo = True
            return self.send_response()
        elif p.haslayer(OFPTGetConfigRequest):
            self.answer_config = True
            self.counter += 1
            return self.send_response()
        elif p.haslayer(OFPTBarrierRequest):
            self.answer_barrier = True
            return self.send_response()
        else:
            for c in ofp_multipart_request_cls:
                if p.haslayer(ofp_multipart_request_cls[c]):
                    self.stats_index = c
                    self.answer_stats = True
                    return self.send_response()
        return None

    def send_response(self):
        if self.echo:
            self.counter_dict['echo'] += 1
            self.echo = False
            print("ECHOO ")
            return OFPTEchoReply()
        elif self.answer_config:
            self.counter_dict['config'] += 1
            self.answer_config = False
            print("Answer config ")
            return OFPTGetConfigReply()
        elif self.answer_features:
            self.counter_dict['features'] += 1
            self.answer_features = False
            print("Answer features ")
            return OFPTFeaturesReply()
        elif self.answer_barrier:
            self.counter_dict['barrier'] += 1
            self.answer_barrier = False
            print("Answer barrier ")
            return OFPTBarrierReply()
        elif self.answer_stats:
            self.counter_dict['stats'] += 1
            self.answer_stats = False
            print("Answer stats ")
            return ofp_multipart_reply_cls[self.stats_index]()
        return None

    def launch(self):
        pass
