from scapy.all import Packet, sniff


def receive_target_packet() -> Packet:
    """Sniffs and receives a single target ICMP packet
    that is sent by `icmp_sender.py`.

    The packet is filtered by the following conditions:

    1. Sent by the sender host to receiver host
    2. It has the TTL value of 1
    3. It is an ICMP echo-request packet

    Returns:
        Packet: The received ICMP target packet.
    """
    filter = "icmp"
    filter += " and src host sender"
    filter += " and dst host receiver"
    filter += " and ip[8] == 1"
    filter += " and icmp[icmptype] == icmp-echo"
    packets = sniff(filter=filter, count=1)
    return packets[0]


def print_received() -> None:
    """Receives and prints the target ICMP packet sent by `icmp_sender.py`"""
    target_packet = receive_target_packet()
    target_packet.show()


if __name__ == "__main__":
    print_received()
