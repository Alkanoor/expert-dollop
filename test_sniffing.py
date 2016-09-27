from sniff_thread import *
from tcp_handshake import *
from south_spoofing_scenario import *


t = TcpHandshake(("192.168.56.102",6633))
t.start()

sniffing_thread = Sniff_thread("vboxnet0","192.168.56.102",6633,t.sport,1000)
sniffing_thread.threaded_sniff()

analyse_scenario = South_spoofing_scenario(sniffing_thread,t)
analyse_scenario.launch()
