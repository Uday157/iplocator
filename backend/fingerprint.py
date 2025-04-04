import re

def fingerprint_device(scan_result):
    ports = scan_result.get('open_ports', [])
    services = scan_result.get('services', [])
    mac_address = scan_result.get('mac_address', None)  # If retrievable
    os_info = scan_result.get('os', "").lower()  # OS Detection if available
    device_type = "Unknown Device"

    # Port-Based Identification
    if 554 in ports:
        device_type = "IP Camera (RTSP Streaming)"
    elif 1883 in ports or 8883 in ports:
        device_type = "IoT Sensor / Gateway (MQTT Broker)"
    elif 80 in ports or 443 in ports:
        if any("nginx" in svc.lower() or "apache" in svc.lower() for svc in services):
            device_type = "Smart Hub / IoT Web Interface"
        else:
            device_type = "Generic IoT Device with Web UI"
    elif 5000 in ports or 1900 in ports:
        device_type = "Smart Speaker / Media Device (UPnP)"
    elif 22 in ports and "linux" in os_info:
        device_type = "Linux Server / Embedded Linux Device (SSH Enabled)"
    elif 3389 in ports:
        device_type = "Windows PC / Server (RDP Enabled)"
    elif 53 in ports:
        device_type = "DNS Server"
    elif 5060 in ports or 5061 in ports:
        device_type = "VoIP Device (SIP Server)"
    elif 67 in ports and 68 in ports:
        device_type = "Router / DHCP Server"
    elif 5353 in ports:
        device_type = "Apple Device (Bonjour Service)"
    elif 9100 in ports:
        device_type = "Network Printer"
    elif 161 in ports or 162 in ports:
        device_type = "SNMP-enabled Network Device"

    # OS-Based Identification
    if "windows" in os_info:
        device_type = "Windows PC / Laptop"
    elif "linux" in os_info and "desktop" in os_info:
        device_type = "Linux PC / Laptop"
    elif "linux" in os_info and "router" in os_info:
        device_type = "Linux-based Router"
    elif "android" in os_info:
        device_type = "Android Mobile Device"
    elif "ios" in os_info or "mac" in os_info:
        device_type = "Apple Device"
    elif "vmware" in os_info or any("vmware" in svc.lower() for svc in services):
        device_type = "Virtual Machine (VMware)"

    # MAC Address-Based Identification (If Available)
    if mac_address:
        mac_prefix = mac_address[:8].upper()  # First 8 characters
        if re.match(r"00:1A:79|00:1B:44", mac_prefix):
            device_type = "CCTV Camera (Hikvision)"
        elif re.match(r"00:50:56", mac_prefix):
            device_type = "VMware Virtual Machine"
        elif re.match(r"BC:92:6B|D8:50:E6", mac_prefix):
            device_type = "WiFi Router / Access Point"
        elif re.match(r"00:25:9C|00:1C:42", mac_prefix):
            device_type = "Dell Laptop / PC"
        elif re.match(r"FC:15:B4|F8:28:19", mac_prefix):
            device_type = "Apple MacBook / iMac"

    return device_type


# Demo runner
if __name__ == "__main__":
    # Fake data to test without scanner.py
    dummy_result = {
        'ip': '192.168.1.13',
        'open_ports': [22, 80, 554, 67, 5060],
        'services': [
            '22 , OpenSSH , 7.9',
            '80 , nginx , 1.14',
            '554 , RTSP , 1.0',
            '67 , dhcp , N/A',
            '5060 , sip , Asterisk PBX'
        ],
        'mac_address': "00:1A:79:12:34:56",
        'os': "Linux router"
    }
    prediction = fingerprint_device(dummy_result)
    print(f"[+] Likely Device Type: {prediction}")
