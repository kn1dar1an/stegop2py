import queue
import time
from connection import Connection
from window_manager import WindowManager


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
        self.serv_port = 12321
        self.clnt_port = self.serv_port + 1
        self.messages = queue.Queue()
        self.connection = Connection(serv_addr=self.lcl_addr,
                                     serv_port=self.serv_port,
                                     messages_queue=self.messages)
        self.window_manager = WindowManager(self.messages, self.input_callback)

        # Try to connect, or listen for connections
        self.setup(rmt_addr)

    def setup(self, rmt_addr: str) -> None:
        """Setup necessary stuff
        Try to connect to host, if not successful listen for connections
        """
        # The host on the other end should also be listening on the same port
        if not self.connection.connect(rmt_addr, self.serv_port):
            self.rmt_addr = self.connection.listen_for_connections()
            self.connection.setDaemon(True)

        input("\nPress enter key to continue...")

        self.window_manager.start()

    def start(self) -> None:
        """Starts listener
        """
        # Start connection thread
        self.connection.start()
        self.running = True

        while self.running:
            time.sleep(0.001)
            pass

        return

    def stop(self):
        """Stop and close everything
        """
        self.running = False
        self.window_manager.stop()
        self.connection.stop()

    def input_callback(self, outgoing_message):
        self.connection.queue_outgoing(outgoing_message)
        pass