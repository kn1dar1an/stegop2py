import socket
import queue
import random
from threading import Thread
from scapy.all import Raw, StreamSocket, IP, TCP, sr1, send, conf


class Connection(Thread):
    """ Class that contains the raw socket and handles incoming data.
    Implementation is simple and takes into account very basic error
    handling.
    """
    def __init__(self, addr: str, port: int, messages_queue: queue.Queue):
        """Class constructor

        Args:
            addr (str): The address at which to serve. Local IP, or public IP
                        (if behind a nat, port-forwarding must be enabled).
            port (int): Port nuber on which to listen to.
            messages_queue (queue.Queue): Queue for storing plain-text messages
        """
        super(Connection, self).__init__()
        self.lstn_addr = addr
        self.lstn_port = port
        self.messages = messages_queue
        self.host_addr = ""
        self.host_port = 0
        self.listening = False
        self.connected = False
        # Create raw socket and tune to TCP protocol
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_TCP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Convert to scapy SuperSocket
        self.socket = StreamSocket(self.socket, Raw)
        self.lstn_seq = 0
        self.host_seq = 0

        # disable scapy output
        conf.verb = 0

    def run(self) -> None:
        # Start thread
        try:
            self.listening = True
            while self.listening:
                packet = self.listen_for_packet()
                if packet[TCP].flags == "R" or packet[TCP].flags == "RA":
                    # Terminate on RST
                    self.stop()
                else:
                    self.messages.put(("host", packet))

        except ListenerConnectException as e:
            print(f"Listener connect(). {e.reason}")

        except Exception as e:
            print(f"Listener run(). {e}")

        finally:
            return

    def listen_for_connections(self) -> None:
        """Creates socket and listens for connections

        Raises:
            ListenerConnectException: Raised when connection failed
        """
        try:
            print(f"Waiting for connections on port {self.lstn_port}")

            # Receive connection request
            while True:
                packet = self.listen_for_packet(acknowledge=False)
                if packet[TCP].flags == "S":
                    if self.handle_three_way_hs(packet):
                        self.host_addr = packet["IP"].src
                        self.host_port = packet["TCP"].sport
                        break
                    else:
                        raise ListenerConnectException(
                            "Couldn't complete connection")

        except Exception as e:
            raise ListenerConnectException(f"{e}")

        self.connected = True
        print(f"{self.host_addr} has connected!")

    def handle_three_way_hs(self, incoming_syn: IP) -> bool:
        """
        Handles 3-Way-Handlshake for incomming connections
        """
        # 32bit ISN. TODO: Stego ISN
        self.lstn_seq = random.randrange(0, 2**32)
        self.host_seq = incoming_syn[TCP].seq
        synack = IP(src=self.lstn_addr, dst=incoming_syn["IP"].src) / TCP(
            dport=incoming_syn["TCP"].sport,
            sport=self.lstn_port,
            flags="SA",
            seq=self.lstn_seq,
            ack=self.host_seq + 1)

        response = sr1(synack)
        if response["TCP"].flags == "A":
            self.lstn_seq += 1
            self.host_seq = response["TCP"].seq
            return True
        return False

    def listen_for_packet(self, acknowledge=True) -> IP:
        """Recieves a packet directed to us. It is filtered out from the all
        other traffic manually. ACKs are sent when not in 3WHS
        """
        while True:
            data = self.socket.recv(65566)
            packet = IP(bytes(data))
            if packet[IP].dst == self.lstn_addr and packet[TCP].dport == self.lstn_port:
                # TCP Seq is always ISN + 1 after 3WHS because no data is being
                # sent on this socket, other than SYNACKs and ACKs. Host's tcp
                # seq is now previous value + current payload length. Assigning
                # ACK number accordingly.
                if acknowledge:
                    self.host_seq += len(packet["TCP"].payload)
                    ack = IP(src=self.lstn_addr, dst=self.lstn_addr) / TCP(
                        dport=self.host_port,
                        sport=self.lstn_port,
                        flags="A",
                        seq=self.lstn_seq,
                        ack=self.host_seq)
                    send(ack, return_packets=False)
                return packet

    def stop(self) -> None:
        """Stop listening for messages and close socket
        """
        self.listening = False
        self.socket.close()
        self.connected = False


class ListenerConnectException(Exception):
    def __init__(self, reason):
        self.reason = reason
