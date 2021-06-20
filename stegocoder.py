import cryptography


class Stegocoder:
    """ Class that contains the stego-keys (ISNs) and functions used for
    embedding extracting messages from raw data from packets.

    The messages are first encrypted with a secret key. Then, embedded in a chain of random bits
    at an offset (the stego-key). The stego-key is communicated to the other party via ISNs

    This implementation is a PoC of steganography in networking environments. In the future,
    it would be great to implement TLS1.3 to send the chain of random bits with the embedded
    message as data sent via TCP is unencrypted.
    """
    def __init__(self):
        self.serv_isn = 0
        self.clnt_isn = 0
        pass

    def get_encoding_ISN(self) -> int:
        """Generates and returns local ISN as stego-key for encoding

        Returns:
            int: local ISN / data offset-key
        """
        pass

    def set_decoding_ISN(self, isn: int) -> None:
        """Sets the connecting client's ISN as stego-key for decoding after TCP HS

        Args:
            isn (int): connecting client's ISN
        """
        self.clnt_isn = isn

    def encode(self, msg: str) -> bytes:
        """Encodes outgoing message

        Args:
            msg (str): Message to encode

        Returns:
            bytes: Raw bytes with encoded message at the offset
        """
        pass

    def decode(self, data: bytes) -> str:
        """Decodes incoming message using key

        Args:
            data (bytes): Data yet to be decoded

        Returns:
            str: Decoded message
        """
        pass
