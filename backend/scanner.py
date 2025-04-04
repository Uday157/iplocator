import nmap
import re
import socket

def resolve_domain(domain):
    """Resolve a domain to its IP address (IPv4 or IPv6)."""
    try:
        ip = socket.getaddrinfo(domain, None, socket.AF_UNSPEC)[0][4][0]
        return ip
    except Exception as e:
        print(f"[!] Failed to resolve domain {domain}: {e}")
        return None

def scan_target(ip_or_domain):
    """
    Scans the target IP or domain using Nmap and returns structured scan results.
    Supports both IPv4 and IPv6 scanning.
    """
    nm = nmap.PortScanner()
    
    # If input is a domain, resolve to an IP
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$", ip_or_domain):
        print(f"[INFO] Resolving domain: {ip_or_domain}")
        resolved_ip = resolve_domain(ip_or_domain)
        if not resolved_ip:
            return None
        ip = resolved_ip
    else:
        ip = ip_or_domain

    print(f"[+] Scanning IP: {ip} ...")
    
    # Determine if it's an IPv6 address
    is_ipv6 = ":" in ip

    try:
        scan_args = "-6 -sV" if is_ipv6 else "-sV -O"
        nm.scan(ip, arguments=scan_args)
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return None

    result = {
        "ip": ip,
        "open_ports": [],
        "services": [],
        "mac_address": "N/A",
        "os": "N/A",
        "original_input": ip_or_domain,  # Stores domain if scanned
    }

    for host in nm.all_hosts():
        # Retrieve OS information (Only available in IPv4 mode)
        if not is_ipv6 and "osmatch" in nm[host]:
            os_info = nm[host]["osmatch"]
            if os_info:
                result["os"] = os_info[0]["name"]

        # Retrieve MAC Address (Only if available)
        if "addresses" in nm[host] and "mac" in nm[host]["addresses"]:
            result["mac_address"] = nm[host]["addresses"]["mac"]

        # Retrieve open ports and services
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service_name = nm[host][proto][port].get("name", "Unknown")
                service_version = nm[host][proto][port].get("version", "").strip()

                # Handle empty fields with defaults
                if not service_name:
                    service_name = "Unknown"
                if not service_version:
                    service_version = "N/A"

                service_info = f"{port} , {service_name} , {service_version}"
                result["open_ports"].append(port)
                result["services"].append(service_info)

    return result

# For direct testing
if __name__ == "__main__":
    target = input("Enter IP or domain to scan: ")
    output = scan_target(target)
    print(output)