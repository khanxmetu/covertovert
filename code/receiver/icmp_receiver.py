import socket
from typing import Optional

from scapy.all import ICMP, IP, Packet, sniff


def _resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address.

    Args:
        hostname (str): The hostname to resolve.

    Returns:
        Optional[str]: The IP address if successfully resolved, None otherwise.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def receive_icmp_packet() -> Packet:
    """Sniffs for a single ICMP packet.

    Returns:
        Packet: The sniffed ICMP packet.
    """
    packets = sniff(filter="icmp", count=1)
    if packets:
        return packets[0]


def is_target_packet(packet: Packet) -> bool:
    """Check for the conditions to ensure that the packet
    is the one sent by `icmp_sender.py`.

    Namely the following conditions are checked:

    1. Sent by the sender host to receiver host
    2. It has the TTL value of 1
    3. It is an ICMP echo-request packet

    Args:
        packet (Packet): The packet to check.

    Returns:
        bool: The return value. True if target packet, False otherwise.
    """
    if IP not in packet or ICMP not in packet:
        return False

    from_sender = packet[IP].src == _resolve_hostname("sender")
    to_receiver = packet[IP].dst == _resolve_hostname("receiver")
    icmp_echo = packet[ICMP].type == 8
    ttl1 = packet[IP].ttl == 1
    return all([from_sender, to_receiver, icmp_echo, ttl1])


def receive_target_packet() -> Packet:
    """Waits to receive the ICMP packet sent by `icmp_sender.py`
    and returns it.

    Returns:
        Packet: The received target packet.
    """
    while True:
        packet = receive_icmp_packet()
        if is_target_packet(packet):
            return packet


def print_received() -> None:
    """Receives and prints the ICMP packet sent by `icmp_sender.py`"""
    target_packet = receive_target_packet()
    target_packet.show()


if __name__ == "__main__":
    print_received()
