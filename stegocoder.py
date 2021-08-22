import random
import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class Stegocoder:
    """ Class that contains the stego-keys (ISNs) and functions used for
    embedding extracting messages from raw ciphertext from packets.

    The messages are first encrypted with a secret key. Then, embedded in a chain of random
    bits at an offset (the stego-key). The stego-key is communicated to the other party via 
    ISNs.

    This implementation is a PoC of steganography in networking environments. In the future,
    it would be great to implement TLS1.3 to send the chain of random bits with the embedded
    message as ciphertext sent via TCP is unencrypted.

    To be able to decode the message, the stego-text will be stored in the IP ID field for
    these purposes, and the offset in the ISN of the TCP connection. THe offset won't change
    until restarting.
    """

    def __init__(self, password: str):
        self.slt_size = 16  # Salt size, could be anything
        self.key_size = 32  # For AES256
        self.nce_size = 16  # AES Nonce / IV size

        self.password = password  # Pre-shared password

        self.serv_data_offset = int.from_bytes(random.randbytes(1),
                                               byteorder=sys.byteorder)  # Generate random byte for offset
        self.clnt_data_offset = 0

    def get_encoding_isn(self) -> int:
        """Generates and returns local ISN as stego-key for encoding.
        The lowest byte will contain the data offset. 0-255

        Returns:
            int: local ISN / ciphertext offset-key.
        """
        serv_isn = random.getrandbits(32)
        self.serv_data_offset = serv_isn & (0xff << 8) >> 8  # get lowest significant byte
        return int(serv_isn)

    def set_decoding_offset(self, isn: int) -> None:
        """Sets the connecting client's ISN as stego-key for decoding after TCP handshake.

        Args:
            isn (int): connecting client's ISN.
        """
        self.clnt_data_offset = isn & (0xff << 8) >> 8  # Get lowest significant byte

    def stegoencode(self, plaintext: str) -> (bytes, int):
        """Embed message in random chain of bits.

        Args:
            message (int): the 32 bit integer from the IP ID Header Field which contains
            the length of the stegotext.

        Returns
            (bytes, int): Tuple with the bytes chain, and the corresponding IP ID field 
                        value with the length.
        """
        # Encrypt message
        ciphertext = self.encrypt(plaintext)

        # Get length
        message_length = len(ciphertext)

        # Check if length is larger than 255 (max int for 1 byte)
        if message_length > 255:
            raise Exception("Message too long!")

        # Generate random bytes at from 1-2 times the length of the message
        size = random.randint(1 * message_length, 2 * message_length) + self.serv_data_offset
        randomness = random.randbytes(size)

        # Embed message starting at offset
        stegotext = randomness[0:self.serv_data_offset] + ciphertext + randomness[self.serv_data_offset + message_length:]
        ipid = random.randbytes(1) + message_length.to_bytes(1, 'big')

        return (stegotext, int.from_bytes(ipid, 'big'))

    def stegodecode(self, stegotext: bytes, ipid: int) -> str:
        """Steganalysis. Retrieve message embedded in random data.

        Args:
            stegotext (bytes): The TCP payload that has an embedded message.

            ipid (int): The 32 bit integer from the IP ID Header Field which contains
            the length of the stegotext.

        Returns:
            str: The plaintext.
        """

        # Get th e length from IP ID
        length = ipid & (0xff << 8) >> 8  # Get the lowest (rightmost) byte from the ipid field

        # Get encrypted message from stegotext
        ciphertext = stegotext[self.clnt_data_offset:self.clnt_data_offset + length]

        # Decrypt message
        plaintext = self.decrypt(ciphertext)

        return plaintext

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypts outgoing message into ciphertext.

        Args:
            plaintext (str): Message to encrypt.

        Returns:
            bytes: Bytes ciphertext.
        """

        # generate salt every time
        salt = Random.new().read(self.slt_size)
        # Derive a key based on password and salt for generating a nonce/iv and aes key for encryption
        # using PBKDF2 algorithm every time
        derived_key = PBKDF2(password=self.password, salt=salt, dkLen=self.nce_size + self.key_size)

        # Derive nonce/iv and key from PBKDF2 algo
        aes_nonce = derived_key[0:self.nce_size]
        aes_key = derived_key[self.nce_size:]

        # New AES-256 instance
        aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_nonce)

        # Generate the ciphertext = salt + encrypted message
        ciphertext = salt + aes_cipher.encrypt(bytes(plaintext, 'utf-8'))

        # Return ciphertext
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypts plaintext from ciphertext.

        Args:
            ciphertext (bytes): Data yet to be decoded.

        Returns:
            str: Decoded message.
        """
        # Get salt from ciphertext
        salt = ciphertext[0:self.slt_size]


        # Derive a key based on password and received salt for generating a nonce/iv and 
        # AES key for decryption
        derived_key = PBKDF2(password=self.password, salt=salt, dkLen=self.nce_size + self.key_size)

        # Derive nonce/iv and key from PBKDF2 algo
        aes_nonce = derived_key[0:self.nce_size]
        aes_key = derived_key[self.nce_size:]

        # New AES-256 instance
        aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_nonce)

        # Decrypt plaintext from received ciphertext after salt
        plaintext = aes_cipher.decrypt(ciphertext[self.slt_size:])

        # Return UTF-8 string
        return str(plaintext, 'utf-8')
