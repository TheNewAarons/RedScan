import streamlit as st
import pandas as pd
import time
import os
import threading
try:
    import scanner
    import monitor
    import manager
    import net_utils as utils
except ImportError:
    from network_tool import scanner, monitor, manager, net_utils as utils

st.set_page_config(page_title="Network Monitor", layout="wide")

def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

try:
    load_css("network_tool/assets/custom.css")
except FileNotFoundError:
    try:
        load_css("assets/custom.css")
    except:
        pass

if 'devices' not in st.session_state:
    st.session_state.devices = pd.DataFrame(columns=["IP", "MAC", "Hostname", "Vendor"])
if 'monitor_data' not in st.session_state:
    st.session_state.monitor_data = pd.DataFrame(columns=["Time", "Source", "Protocol", "Info"])
if 'monitoring_target' not in st.session_state:
    st.session_state.monitoring_target = None
if 'blocking_target' not in st.session_state:
    st.session_state.blocking_target = None

if 'sniffer' not in st.session_state:
    st.session_state.sniffer = monitor.PacketSniffer()
if 'net_manager' not in st.session_state:
    st.session_state.net_manager = manager.NetworkManager()

st.title("Network Monitor & Manager")
st.markdown("### Local Network Security Tool")

with st.sidebar:
    st.header("Settings")
    all_interfaces = utils.list_interfaces()
    
    best_default = utils.get_interface()
    try:
        default_index = all_interfaces.index(best_default)
    except ValueError:
        default_index = 0
        
    interface = st.selectbox("Network Interface", options=all_interfaces, index=default_index)
    
    current_ip = utils.get_interface_ip(interface)
    default_ip_range = utils.get_local_subnet(interface)
    default_gateway = utils.get_gateway_ip(interface)
    
    st.caption(f"Selected Interface IP: {current_ip}")
    
    gateway_ip = st.text_input("Gateway IP", value=default_gateway)
    ip_range = st.text_input("IP Range to Scan", value=default_ip_range)

    if st.button("Detect / Refresh Info"):
        detected = utils.get_interface()
        st.success(f"Detected Interface: {detected}")

tab1, tab2, tab3 = st.tabs(["Scanner", "Traffic Monitor", "Access Management"])

with tab1:
    st.header("Device Scanner")
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("Start Scan", type="primary"):
            with st.spinner("Scanning network..."):
                try:
                    df = scanner.scan_network(ip_range)
                    st.session_state.devices = df
                    st.success(f"Found {len(df)} devices.")
                except Exception as e:
                    st.error(f"Scan failed: {e}. Try running with sudo.")
        
        if st.button("Deep Scan (Identify OS)"):
            if st.session_state.devices is None or st.session_state.devices.empty:
                st.warning("Run a normal scan first.")
            else:
                with st.spinner("Running deep scan (this takes time per device)..."):
                    detailed_df = scanner.scan_network_details(st.session_state.devices)
                    st.session_state.devices = detailed_df
                    st.success("Deep scan complete.")
    
    st.dataframe(st.session_state.devices, use_container_width=True)

with tab2:
    st.header("Real-Time Traffic Monitor")
    
    if st.session_state.devices is not None and not st.session_state.devices.empty:
        target_options = st.session_state.devices['IP'].tolist()
    else:
        target_options = []
        
    target_ip = st.selectbox("Select Target Device", options=["All"] + target_options)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Monitoring"):
            target = None if target_ip == "All" else target_ip
            st.session_state.monitoring_target = target
            st.session_state.sniffer.start(interface, target)
            st.success(f"Started monitoring {target_ip}")
            
    with col2:
        if st.button("Stop Monitoring"):
            st.session_state.sniffer.stop()
            st.warning("Stopped monitoring.")
            st.session_state.monitoring_target = None

    placeholder = st.empty()
    
    if st.session_state.monitoring_target is not None:
        st.info("Monitoring active... Press 'Stop Monitoring' elsewhere to end.")
        
        col_metric1, col_metric2 = st.columns(2)
        with col_metric1:
            metric_placeholder = st.empty()
        with col_metric2:
            status_placeholder = st.empty()
            
        data_placeholder = st.empty()
        chart_placeholder = st.empty()
        
        while st.session_state.monitoring_target is not None:
            new_data = st.session_state.sniffer.get_data()
            st.session_state.monitor_data = new_data
            
            p_count = len(new_data)
            
            metric_placeholder.metric("Packets Captured", p_count)
            status_placeholder.markdown(f"**Status:** 🟢 Capturing... ({time.strftime('%H:%M:%S')})")
            
            with data_placeholder.container():
                if not new_data.empty:
                    display_df = new_data.iloc[::-1]
                    st.dataframe(display_df.head(100), use_container_width=True)
                else:
                    st.warning("No packets found yet. Try browsing the web or pinging 8.8.8.8")
                
            with chart_placeholder.container():
                if not new_data.empty and 'Protocol' in new_data.columns:
                    proto_counts = new_data['Protocol'].value_counts()
                    st.bar_chart(proto_counts)
            
            time.sleep(0.5)

with tab3:
    st.header("Access Management")
    st.warning("Strictly for personal network testing only.")
    
    block_target = st.selectbox("Target to Block", options=target_options, key="block_select")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Block Internet Access", type="primary"):
            if block_target:
                st.session_state.blocking_target = block_target
                st.session_state.net_manager.start_blocking(block_target, gateway_ip, interface)
                st.error(f"Blocking internet for {block_target}...")
            else:
                st.error("Select a target first.")
                
    with col2:
        if st.button("Restore Access"):
            if st.session_state.blocking_target:
                st.session_state.net_manager.stop_blocking()
                st.success(f"Restored access for {st.session_state.blocking_target}.")
                st.session_state.blocking_target = None
            else:
                st.info("No active blocking rules.")

st.markdown("---")
st.markdown("*Run with sudo for full functionality*")
