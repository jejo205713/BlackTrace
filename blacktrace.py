import subprocess
import re
import time
from ipaddress import ip_address, ip_network

# Define trusted internal network (customize this based on your setup)
TRUSTED_NETWORK = ip_network("192.168.0.0/16")
WHITELIST_IPS = ["127.0.0.1", "0.0.0.0", "::1"]

# Ports commonly used for backdoors (you can extend this list)
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 12345, 31337]

def get_active_connections():
    """Get active network connections using ss."""
    try:
        result = subprocess.check_output(["ss", "-tunap"], stderr=subprocess.DEVNULL).decode()
        return result.splitlines()
    except Exception as e:
        print(f"Error retrieving connections: {e}")
        return []

def is_suspicious(remote_ip, remote_port):
    """Determine if a connection is suspicious."""
    try:
        ip_obj = ip_address(remote_ip)
        if remote_ip in WHITELIST_IPS:
            return False
        if ip_obj in TRUSTED_NETWORK:
            return False
        if int(remote_port) in SUSPICIOUS_PORTS:
            return True
        return True  # External IP not in trusted list
    except Exception:
        return False

def extract_ips_ports(lines):
    """Extract suspicious IPs and ports from ss output."""
    suspicious_ips = set()
    for line in lines:
        match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d+)', line)
        if match:
            ip, port = match.groups()
            if is_suspicious(ip, port):
                suspicious_ips.add(ip)
    return suspicious_ips

def block_ip(ip):
    """Block IP using iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[+] Blocked suspicious IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to block IP: {ip}")

def main():
    print("[*] Scanning for potential backdoor connections...")
    connections = get_active_connections()
    suspects = extract_ips_ports(connections)

    if suspects:
        for ip in suspects:
            block_ip(ip)
    else:
        print("[+] No suspicious connections detected.")

if __name__ == "__main__":
    main()
