import socket
import scapy.all as scapy
import netifaces
import requests

def get_interface():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for link in addrs[netifaces.AF_INET]:
                    if link['addr'] == local_ip:
                        return interface
    except Exception as e:
        print(f"Error detecting interface: {e}")
        return "en0" 
    return "en0"

def list_interfaces():
    return netifaces.interfaces()

def get_interface_ip(interface):
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
    except ValueError:
        pass
    return "127.0.0.1"

def get_local_subnet(interface):
    ip = get_interface_ip(interface)
    if ip == "127.0.0.1":
        return "192.168.1.1/24"
    
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def get_gateway_ip(interface):
    ip = get_interface_ip(interface)
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"
