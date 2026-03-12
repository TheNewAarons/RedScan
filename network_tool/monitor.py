import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import threading
import time
import pandas as pd

import collections

class PacketSniffer:
    def __init__(self):
        self.stop_sniffing = False
        self.packet_data = collections.deque(maxlen=1000)
        self.thread = None
        self.lock = threading.Lock()

    def start(self, interface, target_ip=None):
        self.stop_sniffing = False
        with self.lock:
            self.packet_data.clear() 
        self.thread = threading.Thread(target=self._sniff, args=(interface, target_ip))
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.stop_sniffing = True
        if self.thread and self.thread.is_alive():
            # Scapy's sniff can sometimes be slow to stop
            pass

    def _sniff(self, interface, target_ip):
        def stop_check(x):
            return self.stop_sniffing

        bpf_filter = f"host {target_ip}" if target_ip else None

        # Use filter if target_ip is provided to reduce overhead
        scapy.sniff(
            iface=interface,
            filter=bpf_filter,
            store=False,
            prn=self._process_packet,
            stop_filter=stop_check
        )

    def _process_packet(self, packet):
        if self.stop_sniffing:
            return

        print(".", end="", flush=True) 
        
        timestamp = time.strftime("%H:%M:%S")
        info = ""
        proto = "Other"
        
        if packet.haslayer(HTTPRequest):
            try:
                url = (packet[HTTPRequest].Host.decode(errors='ignore') if packet[HTTPRequest].Host else "") + \
                      (packet[HTTPRequest].Path.decode(errors='ignore') if packet[HTTPRequest].Path else "")
                method = packet[HTTPRequest].Method.decode(errors='ignore')
                info = f"HTTP {method} {url}"
                proto = "HTTP"
            except:
                info = "HTTP Malformed"
                proto = "HTTP"

        elif packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode(errors='ignore')
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
            # Capture other protocols (ICMP, ARP, etc)
            if packet.haslayer(scapy.IP):
                p_num = packet[scapy.IP].proto
                # Map common protocol numbers
                if p_num == 1: proto = "ICMP"
                elif p_num == 6: proto = "TCP"
                elif p_num == 17: proto = "UDP"
                else: proto = f"IP/{p_num}"
                info = packet.summary()
            elif packet.haslayer(scapy.ARP):
                proto = "ARP"
                info = f"ARP {packet[scapy.ARP].op} {packet[scapy.ARP].psrc} -> {packet[scapy.ARP].pdst}"
            elif packet.haslayer(scapy.IPv6):
                proto = "IPv6"
                info = packet.summary()
            else:
                proto = "Other"
                info = packet.summary()

        src_ip = "-"
        dst_ip = "-"
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
        elif packet.haslayer(scapy.IPv6):
            src_ip = packet[scapy.IPv6].src
            dst_ip = packet[scapy.IPv6].dst
        elif packet.haslayer(scapy.ARP):
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst

        with self.lock:
            self.packet_data.append({
                "Time": timestamp,
                "Source": src_ip,
                "Destination": dst_ip,
                "Protocol": proto,
                "Info": info
            })

    def get_data(self):
        with self.lock:
            data = list(self.packet_data)
        
        if not data:
            return pd.DataFrame(columns=["Time", "Source", "Destination", "Protocol", "Info"])
            
        return pd.DataFrame(data)
