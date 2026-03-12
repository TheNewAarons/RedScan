import socket
import scapy.all as scapy
import netifaces
import requests

def get_interface():
    """
    Tries to identify the active network interface by connecting to a public DNS.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Iterate over interfaces to find the one matching local_ip
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for link in addrs[netifaces.AF_INET]:
                        if link['addr'] == local_ip:
                            return interface
            except ValueError:
                continue
    except Exception as e:
        print(f"Error detecting interface: {e}")
        
    # Fallback: return the first interface with an IPv4 address that isn't localhost
    try:
        for interface in netifaces.interfaces():
            if interface == 'lo' or interface.startswith('loop'):
                continue
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return interface
    except:
        pass
        
    return "eth0" # Last resort fallback

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
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            addr_info = addrs[netifaces.AF_INET][0]
            ip = addr_info['addr']
            netmask = addr_info['netmask']

            # Calculate CIDR prefix length
            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))

            # Get network address
            ip_parts = [int(x) for x in ip.split('.')]
            mask_parts = [int(x) for x in netmask.split('.')]
            net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]

            return f"{'.'.join(net_parts)}/{cidr}"
    except Exception as e:
        print(f"Error calculating subnet: {e}")

    # Fallback
    ip = get_interface_ip(interface)
    if ip == "127.0.0.1":
        return "192.168.1.0/24"
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def get_gateway_ip(interface):
    """
    Attempts to identify the gateway IP.
    """
    try:
        gws = netifaces.gateways()
        # Check for default gateway on the specific interface
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            gw_ip, gw_iface = gws['default'][netifaces.AF_INET]
            if gw_iface == interface:
                return gw_ip

        # Check all gateways for this interface
        if netifaces.AF_INET in gws:
            for gw in gws[netifaces.AF_INET]:
                if gw[1] == interface:
                    return gw[0]
    except Exception as e:
        print(f"Error detecting gateway: {e}")
        
    # Fallback to heuristic
    ip = get_interface_ip(interface)
    if ip == "127.0.0.1":
        return "192.168.1.1"
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"

# Simple cache for MAC vendors to avoid rate limits
vendor_cache = {}

def get_mac_vendor(mac_address):
    mac_upper = mac_address.upper()
    if mac_upper in vendor_cache:
        return vendor_cache[mac_upper]
        
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=1) # Reduced timeout
        if response.status_code == 200:
            vendor = response.text
            vendor_cache[mac_upper] = vendor
            return vendor
    except:
        pass
    
    # Cache "Unknown" too to prevent retrying same failed MAC immediately
    vendor_cache[mac_upper] = "Unknown"
    return "Unknown"
