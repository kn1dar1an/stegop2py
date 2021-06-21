import socket
import queue
import random
import sys
import time
import errno
from threading import Thread
from scapy.all import Raw, StreamSocket, IP, TCP, sr1, send, conf
from stegocoder import Stegocoder


class Connection(Thread):
    """ Class that contains the raw socket and handles encoding, decoding, sending, and receiving data.
    Implementation is simple and takes into account very basic error
    handling.
    """

    def __init__(self, password: str, serv_addr: str, serv_port: int, messages_queue: queue.Queue):
        """Class constructor

        Args:
            serv_addr (str): The address at which to serve. Local IP, or public IP
                        (if behind a nat, port-forwarding must be enabled).
            serv_port (int): Port number on which to listen to.
            messages_queue (queue.Queue): Queue for storing plain-text messages
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

        # disable scapy output
        conf.verb = 0

    def run(self) -> None:
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
                        print("No ACK from remote")

                # Check for incoming messages
                packet = self.listen_for_packet()
                if packet:
                    if packet[TCP].flags == "R" or packet[TCP].flags == "RA":
                        # Terminate on RST
                        self.stop()
                    elif packet[TCP].flags == "A":
                        # Ignore ACKs
                        continue
                    else:
                        self.messages.put(("host", self.stegocoder.stegodecode(packet[TCP].payload.load, packet[IP].id)))

                time.sleep(0.001)

        except ListenerConnectException as e:
            print(f"Listener connect(). {e.reason}")

        finally:
            return

    def connect(self, clnt_addr: str, clnt_port: int) -> bool:
        """Attempt to connect to given host. Performs 3WHS

        Args:
            clnt_addr (str): Host's address to attempt to connect to
            clnt_port (int): Host's connecting port

        Returns:
            bool: return True if connection successful, or False if otherwise
        """
        print(f"Attempting to connect to {clnt_addr}")
        if self.initiate_three_way_hs(clnt_addr, clnt_port):
            self.clnt_addr = clnt_addr
            self.clnt_port = clnt_port
            self.connected = True
            print(f"Connected to {clnt_addr}!")

        return self.connected

    def listen_for_connections(self) -> None:
        """Creates socket and listens for connections
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
                    raise ListenerConnectException(
                        "Couldn't complete connection")

            time.sleep(0.001)

        self.connected = True
        print(f"{self.clnt_addr} has connected!")
        return

    def initiate_three_way_hs(self, clnt_addr: str, clnt_port: int) -> bool:
        """
        Initiates a 3WHS to start a connection
        """
        # 32bit ISN. TODO: Stego ISN
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
            self.clnt_seq += synack[TCP].seq
            self.stegocoder.set_decoding_offset(synack[TCP].seq)
            ack = IP(src=self.serv_addr, dst=clnt_addr) / TCP(sport=self.serv_port, dport=clnt_port, flags="A",
                                                              seq=self.serv_seq, ack=self.clnt_seq + 1)
            # Send on Layer 3
            send(ack)
        else:
            print("Malformed response: \n", synack.show())
            return False

        return True

    def handle_three_way_hs(self, incoming_syn: IP) -> bool:
        """Handles 3-Way-Handshake for incoming connections
        """
        # 32bit ISN. TODO: Stego ISN
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
            self.stegocoder.serv_data_offset(clnt_seq)
            return True

        return False

    def listen_for_packet(self, acknowledge=True) -> IP:
        """Receives a packet directed to us. It is filtered out from the all
        other traffic manually. ACKs are sent when not in 3WHS
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
                else:
                    time.sleep(0.001)
                    continue
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # No data is available
                    break
                else:
                    print(e)
                    # Re-raise exception
                    raise
            else:
                return packet

    def send_packet(self, stegotext: bytes, ipid: bytes) -> bool:
        if not self.connected:
            raise Exception("Socket not connected!")

        if stegotext:
            try:
                packet = IP(src=self.serv_addr,
                            dst=self.clnt_addr,
                            id=int.from_bytes(ipid, byteorder=sys.byteorder)) / \
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
                print(f"Failed to send packet: {e}")
                return False

    def queue_outgoing(self, msg):
        if msg:
            self.messages.put(("self", msg))
            self.out_queue.put(msg)

    def stop(self) -> None:
        """Stop listening for messages and close socket
        """
        self.listening = False
        self.socket.close()
        self.connected = False


class ListenerConnectException(Exception):
    def __init__(self, reason):
        self.reason = reason
