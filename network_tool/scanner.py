import scapy.all as scapy
import pandas as pd
import net_utils as utils
import socket
import nmap
from concurrent.futures import ThreadPoolExecutor

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

def scan_network(ip_range):
    print(f"Scanning {ip_range}...")
    devices = [] 
    
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        print(f"Sending ARP broadcast to {ip_range}...")
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, retry=2, verbose=True)[0]
        print(f"Received {len(answered_list)} responses.")
        
        ips = [element[1].psrc for element in answered_list]

        # Parallelize hostname lookups
        with ThreadPoolExecutor(max_workers=20) as executor:
            hostnames = list(executor.map(get_hostname, ips))

        for i, element in enumerate(answered_list):
            ip_addr = element[1].psrc
            mac_addr = element[1].hwsrc
            
            device_info = {
                "IP": ip_addr,
                "MAC": mac_addr,
                "Hostname": hostnames[i],
                "Vendor": utils.get_mac_vendor(mac_addr)
            }
            devices.append(device_info)

    except Exception as e:
        print(f"Error in scan_network: {e}")
        
    return pd.DataFrame(devices)

def scan_network_details(devices_df):
    if devices_df.empty:
        return devices_df

    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("Nmap not found", flush=True)
        return devices_df
    except Exception as e:
        print(f"Nmap error: {e}", flush=True)
        return devices_df

    print("Starting Deep Scan (Nmap)...")
    ips_to_scan = " ".join(devices_df['IP'].tolist())
    
    try:
        # Scan all IPs in one go
        scan_res = nm.scan(ips_to_scan, arguments="-O --osscan-guess -T4")
        
        updated_devices = []
        for _, row in devices_df.iterrows():
            ip = row['IP']
            info = {'OS': "Unknown", 'Type': "Unknown"}
            
            if ip in scan_res['scan']:
                scan_data = scan_res['scan'][ip]
                if 'osmatch' in scan_data and scan_data['osmatch']:
                    os_name = scan_data['osmatch'][0]['name']
                    info['OS'] = os_name
                    
                    if "Windows" in os_name:
                        info['Type'] = "PC/Laptop"
                    elif "Linux" in os_name:
                        info['Type'] = "Server/IoT"
                    elif "iOS" in os_name or "macOS" in os_name:
                        info['Type'] = "Apple Device"
                    elif "Android" in os_name:
                        info['Type'] = "Mobile/Tablet"
                elif 'status' in scan_data and scan_data['status']['state'] == 'down':
                    info['OS'] = "Unreachable"
                    info['Type'] = "?"
            
            updated_row = row.to_dict()
            updated_row.update(info)
            updated_devices.append(updated_row)

        return pd.DataFrame(updated_devices)

    except Exception as e:
        print(f"Bulk Nmap scan error: {e}")
        return devices_df
