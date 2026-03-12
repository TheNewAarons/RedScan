import scapy.all as scapy
import pandas as pd
import net_utils as utils
import socket
import nmap

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
        
        for element in answered_list:
            ip_addr = element[1].psrc
            mac_addr = element[1].hwsrc
            
            try:
                hostname = socket.gethostbyaddr(ip_addr)[0]
            except socket.herror:
                hostname = "Unknown"
                
            device_info = {
                "IP": ip_addr,
                "MAC": mac_addr,
                "Hostname": hostname,
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

    updated_devices = []
    
    print("Starting Deep Scan (Nmap)...")
    
    for _, row in devices_df.iterrows():
        ip = row['IP']
        vendor = row['Vendor']
        info = {}
        
        try:
            print(f"Deep scanning {ip}...")
            scan_res = nm.scan(ip, arguments="-O --osscan-guess -T4")
            
            if ip in scan_res['scan']:
                if 'osmatch' in scan_res['scan'][ip] and scan_res['scan'][ip]['osmatch']:
                    os_name = scan_res['scan'][ip]['osmatch'][0]['name']
                    info['OS'] = os_name
                    
                    if "Windows" in os_name:
                        info['Type'] = "PC/Laptop"
                    elif "Linux" in os_name:
                        info['Type'] = "Server/IoT"
                    elif "iOS" in os_name or "macOS" in os_name:
                        info['Type'] = "Apple Device"
                    elif "Android" in os_name:
                        info['Type'] = "Mobile/Tablet"
                    else:
                        info['Type'] = "Unknown"
                else:
                    info['OS'] = "Unknown"
                    info['Type'] = "Unknown"
            else:
                info['OS'] = "Unreachable"
                info['Type'] = "?"
                
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
            info['OS'] = "Error"
            info['Type'] = "Error"
            
        updated_row = row.to_dict()
        updated_row.update(info)
        updated_devices.append(updated_row)
        
    return pd.DataFrame(updated_devices)
