import os
import sys
import ctypes
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)


def is_nimda_worm(packet):
    # if packet.haslayer(TCP) and packet[TCP].dport == 80:
    #     payload = packet[TCP].payload
    #     return "GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n" in str(payload)
    # return False
    if packet.haslayer(Raw):
        return b"/scripts/root.exe" in bytes(packet[Raw].load)
    return False

def log_event(message):
    log_folders = "logs"
    os.makedirs(log_folders, exist_ok = True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folders, f"log_{timestamp}.txt")

    with open(log_file, "a") as file:
        file.write(f"{message}\n")


def packet_callback(packet):
    src_ip = packet[IP].src

    if src_ip in white_list_ips:
        return
    
    if src_ip in black_list_ips and src_ip not in blocked_ips:
        print(f"Blocking blacklisted IP: {src_ip}")
        os.system(f'netsh advfirewall firewall add rule name="Block_{src_ip}" dir=in action=block remoteip={src_ip}')
        log_event(f"Blocking blacklisted IP: {src_ip}")
        blocked_ips.add(src_ip)
        return

    if is_nimda_worm(packet) and src_ip not in blocked_ips:
        print(f"Blocking nimda src: {src_ip}")
        os.system(f'netsh advfirewall firewall add rule name="Block_{src_ip}" dir=in action=block remoteip={src_ip}')
        log_event(f"Blocking nimda IP: {src_ip}")
        blocked_ips.add(src_ip)
        return

    packet_count[src_ip] += 1
    time_interval = time.time() - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}')
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        start_time[0] = time.time()
        packet_count.clear()







if __name__ == "__main__":
    if not is_admin():
        print("You must access the highest privilege")
        sys.exit(1)

    white_list_ips = read_ip_file("WhiteList.txt")
    black_list_ips = read_ip_file("BlackList.txt")
    
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    

    print("Monitoring network traffic...")
    sniff(filter = "ip", prn = packet_callback)




