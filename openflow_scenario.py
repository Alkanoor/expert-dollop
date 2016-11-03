import time
from scapy.all import *
from scenario import Scenario


class Openflow_scenario(Scenario):

    def __init__(self, sniff_thread, tcp_handshake):
        Scenario.__init__(self, sniff_thread, tcp_handshake)
        self.echo = False
        self.xid = 0
        self.answer_features = False
        self.answer_config = False
        self.answer_barrier = False
        self.answer_role = False
        self.answer_stats = False
        self.answer_stats_ports = False
        self.answer_request_port_desc = False
        self.answer_stats_manufacturer = False
        self.counter_dict = {'echo':0,'config':0,'features':0,'barrier':0,'role':0,'stats':0,'port_desc':0}

    def react_to(self, pkt):
        to_send = []
        for p in pkt:
            cur_payload = p[TCP].payload
            additional_pkts = [cur_payload]

            print(repr(cur_payload))
            if self.is_openflow(p):
                try:
                    while cur_payload.len != len(cur_payload):
                        cur_payload = TCP.guess_payload_class(p[TCP],str(cur_payload.payload))(str(cur_payload.payload))
                        additional_pkts.append(cur_payload)
                        print(repr(cur_payload))
                except Exception, e:
                    print("================================================")
                    print("================================================")
                    print("Shouldn't happen but sometimes ... "+str(e))
                    print("================================================")
                    print("================================================")

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
        tmp = str(p)[4:8]
        if len(tmp)==4:
            self.xid = struct.unpack('>I',tmp)[0]
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
        elif p.haslayer(OFPTRoleRequest):
            self.answer_role = True
            return self.send_response()
        elif p.haslayer(OFPMPRequestPortDesc):
            self.answer_request_port_desc = True
            return self.send_response()
        else:
            for c in ofp_multipart_request_cls:
                if p.haslayer(ofp_multipart_request_cls[c]):
                    self.stats_index = c
                    self.answer_stats = True
                    self.answer_stats_manufacturer = False
                    self.answer_stats_ports = False
                    if p[ofp_multipart_request_cls[c].name].mp_type == 0:
                        self.answer_stats_manufacturer = True
                    elif p[ofp_multipart_request_cls[c].name].mp_type == 13:
                        self.answer_stats_ports = True
                    return self.send_response()
        return None

    def send_response(self):
        if self.echo:
            self.counter_dict['echo'] += 1
            self.echo = False
            print("ECHOO ")
            return OFPTEchoReply(xid=self.xid)
        elif self.answer_config:
            self.counter_dict['config'] += 1
            self.answer_config = False
            print("Answer config ")
            return OFPTGetConfigReply(xid=self.xid, miss_send_len=65535)
        elif self.answer_features:
            self.counter_dict['features'] += 1
            self.answer_features = False
            print("Answer features ")
            return OFPTFeaturesReply(n_buffers=255, n_tables=255, xid=self.xid, datapath_id=8888)
        elif self.answer_barrier:
            self.counter_dict['barrier'] += 1
            self.answer_barrier = False
            print("Answer barrier ")
            return OFPTBarrierReply(xid=self.xid)
        elif self.answer_role:
            self.counter_dict['role'] += 1
            self.answer_role = False
            print("Answer role")
            return OFPTRoleReply(xid=self.xid, role="OFPCR_ROLE_MASTER")
        elif self.answer_request_port_desc:
            self.counter_dict['port_desc'] += 1
            self.answer_request_port_desc = False
            print("Answer port description")
            return OFPMPReplyPortDesc(xid=self.xid, ports=[OFPPort(port_no=1, hw_addr="77:66:33:33:66:77", port_name="theresa lisa", curr="100MB_HD", supported="1TB_FD", curr_speed=100000000)])
        elif self.answer_stats:
            self.counter_dict['stats'] += 1
            self.answer_stats = False
            print("Answer stats ")
            if self.answer_stats_manufacturer:
                return ofp_multipart_reply_cls[self.stats_index](xid=self.xid, mfr_desc="Nicira, Inc.", hw_desc="Open vSwitch", sw_desc="2.3.1", serial_num="None", dp_desc="None")
                return ofp_multipart_reply_cls[self.stats_index](xid=self.xid, mfr_desc="manumanumanu factureur", hw_desc="hardc0r3", sw_desc="s0ftc0re")
            elif self.answer_stats_ports:
                return ofp_multipart_reply_cls[self.stats_index](xid=self.xid, ports=[OFPPort(port_no=1, hw_addr="5e:4d:33:33:d4:e5", port_name="monin terface", curr="100MB_HD", supported="1TB_FD", curr_speed=100000000)])
            else:
                return ofp_multipart_reply_cls[self.stats_index](xid=self.xid)
        return None

    def launch(self):
        pass
