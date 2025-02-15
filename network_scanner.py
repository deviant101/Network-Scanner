from scapy.all import sr1, sr, IP, ICMP, TCP, UDP, SCTP, ARP
from typing import Optional

def icmp_ping(host: str) -> Optional[IP]:
    """Send ICMP echo request to host.
    
    Args:
        host: Target IP address
    Returns:
        Response packet or None if no response
    """
    return sr1(IP(dst=host)/ICMP(), timeout=2, verbose=False)

def tcp_ack_ping(host, port=80):
    return sr1(IP(dst=host)/TCP(dport=port, flags="A"), timeout=2)

def sctp_init_ping(host, port=80):
    return sr1(IP(dst=host)/SCTP(dport=port), timeout=2)

def icmp_timestamp_ping(host):
    return sr1(IP(dst=host)/ICMP(type=13), timeout=2)

def icmp_address_mask_ping(host):
    return sr1(IP(dst=host)/ICMP(type=17), timeout=2)

def arp_ping(host):
    return sr1(ARP(pdst=host), timeout=2)

def get_mac_address(host):
    ans, _ = sr(ARP(pdst=host), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def os_detection(host):
    response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=False)
    if response:
        ttl = response.ttl
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"
    return None

def tcp_connect_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=2, verbose=False)
    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return "Open"
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return "Closed"
    return "Filtered"

def udp_scan(host, port):
    response = sr1(IP(dst=host)/UDP(dport=port), timeout=2, verbose=False)
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(UDP):
        return "Open"
    elif response.haslayer(ICMP):
        icmp_type = response.getlayer(ICMP).type
        icmp_code = response.getlayer(ICMP).code
        if icmp_type == 3 and icmp_code == 3:
            return "Closed"
        elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
            return "Filtered"
    return "Unknown"

def tcp_null_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags=""), timeout=2, verbose=False)
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        return "Closed"
    return "Filtered"

def tcp_fin_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="F"), timeout=2, verbose=False)
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        return "Closed"
    return "Filtered"

def xmas_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="FPU"), timeout=2, verbose=False)
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        return "Closed"
    return "Filtered"

def tcp_ack_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="A"), timeout=2, verbose=False)
    if response is None:
        return "Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        return "Unfiltered"
    return "Filtered"

def tcp_window_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="A"), timeout=2, verbose=False)
    if response is None:
        return "Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        if response.getlayer(TCP).window == 0:
            return "Closed"
        else:
            return "Open"
    return "Filtered"

def tcp_maimon_scan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port, flags="FPU"), timeout=2, verbose=False)
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        return "Closed"
    return "Filtered"

def ip_protocol_scan(host):
    response = sr1(IP(dst=host)/IP(), timeout=2, verbose=False)
    if response:
        return response.summary()
    return "No response"
