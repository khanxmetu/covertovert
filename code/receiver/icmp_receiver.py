from typing import Optional

from scapy.all import IP, Packet, sniff


def format_callback(packet: Packet) -> Optional[str]:
    """Formats the output to be displayed for the packet.

    This callback function is intended to be used as an argument to `scapy.sendrecv.sniff`.
    Note that the ttl-based filtering (ttl=1) is done here instead of `filter` argument
    to `scapy.sendrecv.sniff` due to the limatations of Berkeley Packet Filter syntax.


    Returns:
        The formatted string to show the packet.
    """
    if packet[IP].ttl != 1:
        return

    return packet.show()


def run_receiver() -> None:
    """Starts the sniffer to filter and print ICMP packets from sender host with ttl=1"""
    sniff(
        prn=format_callback,
        filter="icmp and src host sender and dst host receiver",
        store=0,
    )


if __name__ == "__main__":
    run_receiver()
