from typing import Optional

from scapy.all import IP, Packet, sniff


class Receiver:
    def __init__(self):
        # Flag to track whether the desired packet was received.
        self.has_received = False

    def _format_callback(self, packet: Packet) -> Optional[str]:
        """Formats the output to be displayed for the packet.

        This callback function is intended to be used as an argument to `scapy.sendrecv.sniff`.
        Note that the ttl-based filtering (ttl=1) is done here instead of `filter` argument
        to `scapy.sendrecv.sniff` due to the limatations of Berkeley Packet Filter syntax.


        Returns:
            The formatted string to show the packet.
        """
        if packet[IP].ttl != 1:
            return

        self.has_received = True

        return packet.show()

    def _receive_packet(self) -> None:
        """Receives a single packet ICMP packet from the sender.

        If the packet is the desired packet with ttl=1,
        it prints its details and set the has_received flag to True.
        """
        sniff(
            prn=self._format_callback,
            filter="icmp and src host sender and dst host receiver",
            store=0,
            count=1,
        )

    def run(self) -> None:
        """Receives and prints the ICMP packet from sender with ttl=1 and returns."""
        while not self.has_received:
            self._receive_packet()


if __name__ == "__main__":
    receiver = Receiver()
    receiver.run()
