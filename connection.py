import errno
import logging
import queue
import socket
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread
from scapy.all import Raw, IP, TCP, sr1, send, conf
from stegocoder import Stegocoder
from typing import Callable


class Connection(Thread):
    """ Class that contains the raw socket and handles sending and receiving data.
    Implementation is simple and takes into account very basic error handling.
    """

    def __init__(self, password: str, serv_addr: str, serv_port: int, messages_queue: queue.Queue, print_cb: Callable):
        """Class constructor

        Args:
            password (str): Password used for encrypting and decrypting ciphertexts.
            serv_addr (str): The address at which to serve. Local IP, or public IP
                        (if behind a nat, port-forwarding must be enabled).
            serv_port (int): Port number on which to listen to.
            messages_queue (queue.Queue): Queue for storing plain-text messages.
            print_cb (Callable): Callable function for printing system messages.
        """
        super(Connection, self).__init__()
        self.stegocoder = Stegocoder(password)
        self.serv_addr = serv_addr
        self.clnt_addr = ""
        self.serv_port = serv_port
        self.clnt_port = 0
        self.messages = messages_queue
        self.listening = False
        self.connected = False
        # Create raw socket and tune to TCP protocol
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_TCP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setblocking(False)

        self.serv_seq = 0
        self.clnt_seq = 0
        self.out_queue = queue.Queue()

        self.print_cb = print_cb

        # disable scapy output
        conf.verb = 0

    def run(self) -> None:
        """Override method from Thread class. Starts the main thread loop. Constantly checks
        for queued messages for sending and sends them, and checks for incoming messages and
        prints them to the window.
        """
        # Start thread
        if not self.connected:
            raise Exception("Socket not connected!")
        try:
            self.listening = True

            while self.listening:
                # If any queued messages for sending, send them
                if not self.out_queue.empty():
                    msg = self.out_queue.get()
                    stegotext, ipid = self.stegocoder.stegoencode(msg)
                    if not self.send_packet(stegotext, ipid):
                        self.print_cb("No ACK from remote")

                # Check for incoming messages
                packet = self.listen_for_packet()
                if packet:
                    if packet[TCP].flags == "R" or packet[TCP].flags == "RA":
                        # Terminate on RST
                        self.stop()
                    elif packet[TCP].flags == "A":
                        # Ignore ACKs
                        continue
                    elif Raw in packet:
                        decoded = ""
                        try:
                            decoded = self.stegocoder.stegodecode(packet[Raw].load, packet[IP].id)
                        except UnicodeDecodeError:
                            # If password is incorrect decoding will fail
                            self.print_cb(f" Unicode decode error: check password")
                            pass
                        else:
                            self.messages.put(('host', decoded))
                    else:
                        continue

                time.sleep(0.001)

        except Exception as e:
            print(f"Conenction loop: {e}")

        finally:
            print("connection: exiting loop")
            return

    def connect(self, clnt_addr: str, clnt_port: int) -> bool:
        """Attempt to connect to given host. Performs 3WHS.

        Args:
            clnt_addr (str): Host's address to attempt to connect to.
            clnt_port (int): Host's connecting port.

        Returns:
            bool: return True if connection successful, or False if otherwise.
        """
        print(f"Attempting to connect to {clnt_addr}")
        if self.initiate_three_way_hs(clnt_addr, clnt_port):
            self.clnt_addr = clnt_addr
            self.clnt_port = clnt_port
            self.connected = True
            print(f"Connected to {clnt_addr}!")

        return self.connected

    def listen_for_connections(self) -> None:
        """Creates socket and listens for connections.
        """
        print(f"Waiting for connections on port {self.serv_port}")

        # Receive connection request
        while True:
            packet = self.listen_for_packet(acknowledge=False)
            if packet and packet[TCP].flags == "S":
                if self.handle_three_way_hs(packet):
                    self.clnt_addr = packet[IP].src
                    self.clnt_port = packet[TCP].sport
                    break
                else:
                    print(f"Connection with {packet[IP].src} failed.")
                    continue

            time.sleep(0.001)

        self.connected = True
        print(f"{self.clnt_addr} has connected!")
        return

    def initiate_three_way_hs(self, clnt_addr: str, clnt_port: int) -> bool:
        """
        Initiates a 3WHS to start a connection.

        Args:
            clnt_addr: target host's address.
            clnt_port: target host's port.

        Returns:
            bool: True if successful, False if unsuccessful.
        """
        # 32bit ISN embedded with the data-offset.
        self.serv_seq = self.stegocoder.get_encoding_isn()
        syn = IP(src=self.serv_addr, dst=clnt_addr) / TCP(sport=self.serv_port, dport=clnt_port, flags="S",
                                                          seq=self.serv_seq, ack=0)
        # Try receiving a response 5 times with 2 second timeout
        synack = None
        for _ in range(0, 5):
            synack = sr1(syn, timeout=2)
            if synack:
                break

        if not synack:
            print(f"{clnt_addr} is offline")
            return False

        elif synack[IP].src == clnt_addr and synack[TCP].sport == clnt_port and synack[TCP].flags == "SA":
            self.serv_seq += 1
            self.clnt_seq += synack[TCP].seq + 1
            self.stegocoder.set_decoding_offset(synack[TCP].seq)
            ack = IP(src=self.serv_addr, dst=clnt_addr) / TCP(sport=self.serv_port, dport=clnt_port, flags="A",
                                                              seq=self.serv_seq, ack=self.clnt_seq)
            # Send on Layer 3
            send(ack)
        else:
            print("Malformed response: \n", synack.show())
            return False

        return True

    def handle_three_way_hs(self, incoming_syn: IP) -> bool:
        """Handles 3-Way-Handshake for incoming connections.

        Args:
            incoming_syn (IP): incoming parsed scapy IP packet object with SYN flag set.

        Returns:
            bool: True if successful, False if unsuccessful.
        """
        # 32bit ISN embedded with the data-offset.
        self.serv_seq = self.stegocoder.get_encoding_isn()
        clnt_seq = incoming_syn[TCP].seq
        synack = IP(src=self.serv_addr, dst=incoming_syn[IP].src) / \
                 TCP(dport=incoming_syn[TCP].sport,
                     sport=self.serv_port,
                     flags="SA",
                     seq=self.serv_seq,
                     ack=clnt_seq + 1)

        # Get response
        response = sr1(synack)
        if response[TCP].flags == "A":
            # Is ACK
            self.serv_seq += 1
            self.clnt_seq = response[TCP].seq
            self.stegocoder.set_decoding_offset(clnt_seq)
            return True

        return False

    def listen_for_packet(self, acknowledge=True) -> IP:
        """Receives a packet directed to us. It is filtered out from the all
        other traffic manually. ACKs are sent when not in 3WHS.

        Args:
            acknowledge (bool): if True, incomming packet will be replied to with an ACK
            packed, as per TCP protocol. function can be called with this paramater set to
            False if the purpose is to listen for packets when acknowledgment is already
            handled, for example in the 3WHS.

        Returns:
            IP: returns incomming parsed scapy IP packet object.
        """
        while True:
            try:
                data = self.socket.recv(65535)
                packet = IP(bytes(data))
                if packet[IP].dst == self.serv_addr and packet[TCP].dport == self.serv_port:
                    # TCP Seq is always ISN + 1 after 3WHS because no data is being
                    # sent on this socket, other than SYNACKs and ACKs. Host's tcp
                    # seq is now previous value + current payload length. Assigning
                    # ACK number accordingly.
                    self.clnt_seq += len(bytes(packet[TCP].payload))
                    if acknowledge and packet[TCP].flags != "A":
                        ack = IP(src=self.serv_addr, dst=self.clnt_addr) / TCP(
                            dport=self.clnt_port,
                            sport=self.serv_port,
                            flags="A",
                            seq=self.serv_seq,
                            ack=self.clnt_seq)
                        send(ack)
                    return packet
                else:
                    time.sleep(0.001)
                    continue
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # No data is available
                    break
                else:
                    self.print_cb(e)
                    break

            except Exception as e:
                self.print_cb(e)
                break

    def send_packet(self, stegotext: bytes, ipid: int) -> bool:
        """Sends a forged packet with an embedded message and required stegokeys within
        the packet TCP and IP headers.

        Args:
            stegotext (bytes): Stegotext bytes with embedded encrypted message.
            ipid (int): Identification number with embedded message length to be added to
                        the IPID field in the IP header.

        Returns:
            bool: True if successful, False if unsuccessful.
        """
        if not self.connected:
            raise Exception("Socket not connected!")

        if stegotext:
            try:
                packet = IP(src=self.serv_addr,
                            dst=self.clnt_addr,
                            id=ipid) / \
                         TCP(sport=self.serv_port,
                             dport=self.clnt_port,
                             flags="PA",
                             seq=self.serv_seq,
                             ack=self.clnt_seq) / Raw(stegotext)

                # Send on layer 3
                ack = sr1(packet, timeout=2)
                if ack:
                    self.serv_seq += len(bytes(packet[TCP].payload))
                    return True
                else:
                    return False
            except Exception as e:
                self.print_cb(f"Failed to send packet: {e}")
                return False

    def queue_outgoing(self, msg: str):
        """Adds an outgoing message to the internal message queue, and queues for sending.

        Args:
            msg (str): The message string.
        """
        if msg:
            self.messages.put(("self", msg))
            self.out_queue.put(msg)

    def stop(self) -> None:
        """Stop listening for messages and close socket.
        """
        self.listening = False
        self.socket.close()
        self.connected = False
