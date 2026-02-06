import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import threading
import time
import pandas as pd

class PacketSniffer:
    def __init__(self):
        self.stop_sniffing = False
        self.packet_data = []
        self.thread = None

    def start(self, interface, target_ip=None):
        self.stop_sniffing = False
        self.packet_data = [] 
        self.thread = threading.Thread(target=self._sniff, args=(interface, target_ip))
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.stop_sniffing = True
        if self.thread and self.thread.is_alive():
            pass

    def _sniff(self, interface, target_ip):
        def stop_check(x):
            return self.stop_sniffing

        filter_str = ""
        if target_ip:
            filter_str = f"host {target_ip}"
        
        scapy.sniff(
            iface=interface,
            store=False,
            prn=self._process_packet,
            filter=filter_str,
            stop_filter=stop_check
        )

    def _process_packet(self, packet):
        if self.stop_sniffing:
            return

        print(".", end="", flush=True) 
        
        timestamp = time.strftime("%H:%M:%S")
        
        if packet.haslayer(HTTPRequest):
            try:
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                method = packet[HTTPRequest].Method.decode()
                info = f"HTTP {method} {url}"
                proto = "HTTP"
            except:
                info = "HTTP Malformed"
                proto = "HTTP"

        elif packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode()
                info = f"DNS Query: {query}"
                proto = "DNS"
            except:
                info = "DNS Malformed"
                proto = "DNS"

        elif packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            info = f"TCP {src_port} -> {dst_port}"
            proto = "TCP"
            
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            info = f"UDP {src_port} -> {dst_port}"
            proto = "UDP"
            
        else:
            return

        self.packet_data.append({
            "Time": timestamp,
            "Source": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown",
            "Protocol": proto,
            "Info": info
        })

    def get_data(self):
        return pd.DataFrame(self.packet_data)
