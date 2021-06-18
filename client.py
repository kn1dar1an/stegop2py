import queue
from connection import Connection


class Client:
    def __init__(self, lstn_addr: str, host_addr: str):
        """Class constructor

        Args:
            lstn_addr (str): Address to listen to / Serve on
            host_addr (str): Host's destination address
        """
        self.running = False
        self.lstn_addr = lstn_addr
        self.lstn_port = 12321
        self.host_addr = host_addr
        self.host_port = self.lstn_port + 1
        self.messages = queue.Queue()
        self.connection = Connection(addr=self.lstn_addr,
                                     port=self.lstn_port,
                                     messages_queue=self.messages)
        self.setup()

    def setup(self) -> None:
        """Setup necessary stuff
        Sets up listener connection
        """
        try:
            # The host on the other end should also be listening on the same port
            self.connection.listen_for_connections()
            self.connection.setDaemon(True)
        except Exception as e:
            print(f"setup(): {e}")

    def start(self) -> None:
        """Starts listener
        """
        # Start listener thread
        self.connection.start()
        self.running = True

        while self.running:
            pass

        return 0

    def stop(self):
        """Stop and close everything
        """
        self.running = False
        self.connection.stop()
