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
        # Variables to keep track of receiver state
        # Whether receiver should be stopped
        self.stop_flag = False
        # Count of bits received for the current character
        self.cur_bitcnt = 0
        # Current bitstring for the current character
        self.cur_bitstring = ""
        # Message being received by the receiver
        self.message = ""

        # Disable Scapy verbose mode 
        conf.verb = 0

    def bit_to_random_code(self, bitchr: str) -> int:
        """
        Generates a random integer code between [0, 255] based on the given bitvalue.
        
        Args:
            bitchr (str): Bit character in string representation.

        Returns:
            Random integer code according to the bitvalue.
            Bitvalue: 0 => returns random integer in [0, 127].
            Bitvalue: 1 => returns random integer in [128, 255].
        """
        if bitchr == "0":
            return random.randint(0, 127)
        else:
            return random.randint(128, 255)

    def code_to_bit(self, code: int) -> str:
        """
        Returns the bitvalue corresponding to the given code.
        
        Args:
            code (int): Integer code between [0, 255]

        Returns:
            Bit character in string representation according to the given code.
            Code: [0, 127] => returns "0".
            Code: [128, 255] => returns "1".
        """
        if 0 <= code <= 127:
            return "0"
        elif 128 <= code <= 255:
            return "1"

    def send(self, log_file_name, dst_ip, dst_port) -> None:
        """
        - A random binary message is constructed and logged into the file.
        - The bits of the binary message are processed, 2 bits in each pass.
        - Each bit is transformed into randomly generated 8-bit code.
        - The codes for the 2 bits are combined into a single 16-bit value using bitshifting.
        - A packet is constructed and this value is used as the TCP source port value which is a 16-bit field.
        - Therefore, 2 bits of the original message are transmitted per each packet.
        - The tested throughput using github codespaces is: 128 bits in 2.298 secs => 55.7 bps


        Each bit is encoded as follows:
        - A random integer code is generated based on the given bitvalue.
        - If the bitvalue is 0: a random integer in [0, 127].
        - If the bitvalue is 1: a random integer in [128, 255].
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Traverse through the binary message with a stride of 2.
        for i in range(0, len(binary_message), 2):
            # Extract the 2 bits from the binary message starting at the offset i and encode them.
            bit1_code = self.bit_to_random_code(binary_message[i])
            bit2_code = self.bit_to_random_code(binary_message[i + 1])

            # Combine the two encoded values (8-bits each) into single value 16 bit
            # We achieve this by shifting the first encoded value by 8 bits to left
            # and add the second encoded value.
            src_port = (bit1_code << 8) + bit2_code

            # Make TCP packet, put the encoded value in TCP source port field and send.
            ip = IP(dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port)
            super().send(ip / tcp)

    def recv_message_builder(self, packet) -> None:
        # Extract the encoded value from the TCP source port field.
        src_port = packet["TCP"].sport

        # Extract the first encoded value by shifting 8-bits to left.
        bit1_code = src_port >> 8
        # Extract the second encoded value by selecting on right-most 8 bits.
        bit2_code = src_port & 0xFF

        # Convert the value to the corresponding bitvalues.
        bit1 = self.code_to_bit(bit1_code)
        bit2 = self.code_to_bit(bit2_code)

        # Append the bitvalues to bitstring
        self.cur_bitstring += bit1
        self.cur_bitstring += bit2

        # Increment bit count
        self.cur_bitcnt += 2

        # If all the bits of character are received
        if self.cur_bitcnt == 8:
            char = self.convert_eight_bits_to_character(self.cur_bitstring)
            # Signal the receiver to stop receiving after character received is a full-stop "."
            if char == ".":
                self.stop_flag = True
            # Append the character to the message being built
            self.message += char

            # Reset the bitstring state for the new character to be read
            self.cur_bitcnt = 0
            self.cur_bitstring = ""

    def receive(self, log_file_name, src_ip, dst_ip, dst_port) -> None:
        """
        - Sniff for the packets filtered by their transport type: TCP, source IP: src_ip, destination IP: dst_ip, destination port: dst_port
        - Process each packet with `recv_message_builder` callback.
        - Stop the packet if `self.stop_flag` is set to True

        The processing of each packet is done as follows:
        - The encoded value from the TCP source port field is extracted.
        - Two encoded values are decoded corresponding to two bits of the message.
        - The bitvalues are appended to the bitstring which keeps track of all the bits for the current character being received
        - If the length of bitstring reaches 8, meaning the character is fully received. The bitstring is converted from binary to character and appended to the message being received. 
        - The receiver stops after reading the full-stop "." as it would be the last character of the message.
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
        # The message is logged after being fully received.
        self.log_message(self.message, log_file_name)
