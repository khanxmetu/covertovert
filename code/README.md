# Covert Storage Channel that exploits Protocol Field Manipulation using Source Port field in TCP [Code: CSC-PSV-TCP-SP]

## Introduction

This project is the second phase of the CENG 435 Programming Assignment, focusing on covert communication channels. We implemented a Covert Storage Channel that exploits the Source Port field in TCP to encode and transmit information covertly.

## Encoding

In this project, we used the Protocol Field Manipulation method to send information covertly by changing the Source Port field in TCP headers. This field is 16 bits long, and we divided it into two 8-bit parts. Each part represents one bit of the message. Numbers between 0 and 127 are used for binary 0, and numbers between 128 and 255 are used for binary 1. With this method, each packet can send two bits of the message.

## Sender

Sender creates a random binary message, encodes it into source port values, and sends it to the receiver. It starts by generating a random binary message. As in stated in encoding section, each bit is converted into a source port value based on the encoding rules: numbers between 0 and 127 represent binary 0, and numbers between 128 and 255 represent binary 1. Two bits are combined to make a 16-bit source port value. We used random numbers to make it harder to detect. For each pair of bits, a TCP packet is created using Scapy with the encoded source port, and the packet is sent to the receiver.

## Receiver

The receive function waits for incoming packets, reads the source port field from each packet, and rebuilds the original message. It uses a filter to capture packets sent from given source IP, to a given destination IP and port. For each packet, it takes the source port value and splits it into two parts to decode two bits of the message. These bits are collected until there are 8 bits, which are then converted into a character. If the character is a stop signal (.), the function stops receiving more packets. During this process, the function keeps adding decoded characters to rebuild the full message. Once finished, it saves the complete message in a log file for verification.

## Config

The config.json file contains the settings needed to run the project. The covert_channel_code field is name of the specific method used. Ours are "CSC-PSV-TCP-SP" (Covert Storage Channel using Protocol Field Manipulation with the TCP Source Port). In the send section, there are  the destination IP address (dst_ip), the destination port (dst_port), and the name of the log file (log_file_name) where the sent message is saved. In the receive section, there are source IP address (src_ip), destination IP and port (dst_ip and dst_port), and the log file name for the received message. These ip addresses and destination port are taken as a config paramater to make project more flexible for
## Measured Throughput

We measure the throughut of the sender as 55.7 bits per second for 128 bits length of message.
