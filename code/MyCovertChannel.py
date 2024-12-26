from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, sniff, conf
import random


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    def __init__(self):
        """
        - You can edit __init__.
        """
        self.stop_flag = False
        self.cur_bitcnt = 0
        self.cur_bitstring = ""
        self.message = ""
        conf.verb = 0

    def bit_to_random_code(self, bitchr: str) -> int:
        if bitchr == "0":
            return random.randint(0, 127)
        else:
            return random.randint(128, 255)

    def code_to_bit(self, code: int) -> str:
        if 0 <= code <= 127:
            return "0"
        elif 128 <= code <= 255:
            return "1"

    def send(self, log_file_name, dst_ip, dst_port):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        # throughput test: 128 bits in 2.298 secs => 55.7 bps
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for i in range(0, len(binary_message), 2):
            bit1_code = self.bit_to_random_code(binary_message[i])
            bit2_code = self.bit_to_random_code(binary_message[i + 1])

            src_port = (bit1_code << 8) + bit2_code
            ip = IP(dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port)
            super().send(ip / tcp)

    def recv_message_builder(self, packet):
        src_port = packet["TCP"].sport
        bit1_code = src_port >> 8
        bit2_code = src_port & 0xFF

        bit1 = self.code_to_bit(bit1_code)
        bit2 = self.code_to_bit(bit2_code)

        self.cur_bitstring += bit1
        self.cur_bitstring += bit2

        self.cur_bitcnt += 2

        if self.cur_bitcnt == 8:
            char = self.convert_eight_bits_to_character(self.cur_bitstring)
            if char == ".":
                self.stop_flag = True
            self.message += char
            self.cur_bitcnt = 0
            self.cur_bitstring = ""

    def receive(self, log_file_name, src_ip, dst_ip, dst_port):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        pktfilter = (
            "tcp and src host "
            + src_ip
            + " and dst host "
            + dst_ip
            + " and dst port "
            + str(dst_port)
        )
        sniff(
            filter=pktfilter,
            prn=self.recv_message_builder,
            stop_filter=lambda x: self.stop_flag,
        )
        self.log_message(self.message, log_file_name)
