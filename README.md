## Backdoor

A packet-sniffing backdoor application that:
- reads shell script commands from the client
- executes the shell script commands on the server
- sends the command output to the client
- encrypts sending data using AES cipher with encryption key and salt value
- decrypts receiving data using AES cipher with encryption key and salt value
- prints out the unencrypted data
- sets destination IP address and port number
- sets process name for camouflage

### Install pycryptodome, setproctitle, and Scapy using the commands:

```pip install pycryptodome```

```pip install setproctitle```

```pip install scapy```

### For help function:

```python server.py -h```

```python client.py -h```

### To run server.py:

```python server.py```

```python server.py -n [process_name]```

### To run client.py:

```python client.py -i [dst IP address] -p [dst port]```
