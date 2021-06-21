# stegop2p

This is a small program that creates a Peer-to-peer network with a single host which allows both parties to send
messages to each other.

The messages themselves are placed into in a chain of random bits that simulate "encrypted" data transfer at a specific
offset. To decode the messages this offset, as well as the length of the encoded data that was embedded, are required. 
This information gets sent to the other party by "steganographically" embedding them into the TCP ISN when setting up
the connection and the IP header ID field.

Before being sent the messages are encrypted with a (secret/pre-shared) password with AES CFB Symmetric Encryption. A 
16-bit salt is used along with the password to derive the nonce/iv and the key for the algorithm. The password is input
manually, and the salt is prepended to each message and is counted towrds the message length.

This implementation handles TCP 3WHS-s manually since raw sockets must be used to be able to send forged packets.

### Prerequisites

This project was developed with Python 3.9.5

The following libraries must be installed:
    - scapy: Packet forging library
    - pycryptodome: fork of the dead pycrypto library that is not being maintained 

Due to Linux kernel sending RST TCP segments when no active TCP socket is bound to the port in question, a small "hack"
fixes this issue:
```
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

The port number should also be added to the firewall whitelist

### Usage

#### Note:
Since raw sockets are used, the program must run as superuser
_____________

```
# python ./stegop2p.py <serving address> <initial target host address>
```