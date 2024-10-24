from scapy.all import ICMP, IP, send


def send_pkt() -> None:
    """Sends an ICMP packet with empty payload to receiver host with ttl=1"""
    pkt = IP(dst="receiver", ttl=1) / ICMP()
    send(pkt)


if __name__ == "__main__":
    send_pkt()
