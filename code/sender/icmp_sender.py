from scapy.all import ICMP, IP, send


def send_target_packet() -> None:
    """Sends an ICMP packet with empty payload to receiver host with ttl=1"""
    target_packet = IP(dst="receiver", ttl=1) / ICMP()
    send(target_packet)


if __name__ == "__main__":
    send_target_packet()
