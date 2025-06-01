from scapy.all import rdpcap, IP, UDP, DNS
from collections import defaultdict

pcap_file = "/home/navy/Documents/mqttsn/dns_capture.pcapng"
traffic_stats = defaultdict(lambda: {"in_bytes": 0, "out_bytes": 0})

packets = rdpcap(pcap_file)
for pkt in packets:
  if (IP in pkt) and (UDP in pkt):
    if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        key = (src_ip, src_port, dst_ip, dst_port)
        pkt_size = len(pkt)
        if pkt[UDP].dport == 53:
            traffic_stats[key]["out_bytes"] += pkt_size
        elif pkt[UDP].sport == 53:
            traffic_stats[key]["in_bytes"] += pkt_size
#for debugging start
for key, stats in traffic_stats.items():
    print(key, stats)
#for debuggin end

print("Source IP, Source Port, Destination IP, Destination Port, Incoming Bytes, Outgoing Bytes, Amplification Ratio")
for k, v in traffic_stats.items():
    src_ip, src_port, dst_ip, dst_port = k
    in_b = v["in_bytes"]
    out_b = v["out_bytes"]
    ratio = in_b/out_b if out_b else "N/A"
    print(f"{src_ip},{src_port},{dst_ip},{dst_port},{in_b},{out_b},{ratio}")
