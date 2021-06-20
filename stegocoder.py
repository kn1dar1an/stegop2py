from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random


class Stegocoder:
    """ Class that contains the stego-keys (ISNs) and functions used for
    embedding extracting messages from raw ciphertext from packets.

    The messages are first encrypted with a secret key. Then, embedded in a chain of random bits
    at an offset (the stego-key). The stego-key is communicated to the other party via ISNs

    This implementation is a PoC of steganography in networking environments. In the future,
    it would be great to implement TLS1.3 to send the chain of random bits with the embedded
    message as ciphertext sent via TCP is unencrypted.

    To be able to decode the message, the stego-text length must be known length will be stored in the
    IP ID field for these purposes
    """
    def __init__(self, password: str):
        self.slt_size = 16 # Salt size, could be anything
        self.key_size = 32 # For AES256
        self.nce_size = 16 # AES Nonce / IV size

        self.password = password # Pre-shared password

        self.serv_isn = 0
        self.clnt_isn = 0
        pass

    def get_encoding_isn(self) -> int:
        """Generates and returns local ISN as stego-key for encoding

        Returns:
            int: local ISN / ciphertext offset-key
        """
        pass

    def set_decoding_isn(self, isn: int) -> None:
        """Sets the connecting client's ISN as stego-key for decoding after TCP HS

        Args:
            isn (int): connecting client's ISN
        """
        self.clnt_isn = isn

    def encrypt(self, plaintext: str) -> bytes:
        """Encodes outgoing message

        Args:
            plaintext (str): Message to encode

        Returns:
            bytes: Raw bytes with encoded message at the offset
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
        """Decodes incoming message using key

        Args:
            ciphertext (bytes): Data yet to be decoded

        Returns:
            str: Decoded message
        """
        # Get salt from ciphertext
        salt = ciphertext[0:self.slt_size]

        # Derive a key based on password and received salt for generating a nonce/iv and aes key for decryption
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