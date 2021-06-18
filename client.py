import queue
from connection import Connection


class Client:
    def __init__(self, lcl_addr: str, rmt_addr: str):
        """Class constructor

        Args:
            lcl_addr (str): Address to listen to / Serve on
            rmt_addr (str): Host's destination address
        """
        self.running = False
        self.lcl_addr = lcl_addr
        self.rmt_addr = ""
        self.rx_port = 12321
        self.tx_port = self.rx_port + 1
        self.messages = queue.Queue()
        self.connection = Connection(serv_addr=self.lcl_addr,
                                     serv_port=self.rx_port,
                                     messages_queue=self.messages)

        # Try to connect, or listen for connections
        self.setup(rmt_addr)

    def setup(self, rmt_addr: str) -> None:
        """Setup necessary stuff
        Try to connect to host, if not successful listen for connections
        """
        # The host on the other end should also be listening on the same port
        if not self.connection.connect(rmt_addr, self.rx_port):
            self.rmt_addr = self.connection.listen_for_connections()
            self.connection.setDaemon(True)

    def start(self) -> None:
        """Starts listener
        """
        # Start connection thread
        self.connection.start()
        self.running = True

        while self.running:
            pass

        return

    def stop(self):
        """Stop and close everything
        """
        self.running = False
        self.connection.stop()
