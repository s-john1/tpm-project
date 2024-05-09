import socket

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class Server:
    _sock = None
    _conn = None

    __private_key = None
    _public_key = None

    def __init__(self, listen_addr, port):
        self.listen_addr = listen_addr
        self.port = port

        # Generate RSA encryption keys
        self.generate_keys()

        # Create TCP socket
        self._create_listener()
        self._connect_client()

    def _create_listener(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((self.listen_addr, self.port))
        self._sock.listen()
        print(f"Server listening on {self.listen_addr}:{self.port}")

    def _connect_client(self):
        self._conn = self._sock.accept()
        print("Client connected")

    def receive_message(self):
        data = self._conn[0].recv(4096)
        print("Received encrypted message from client")

        plaintext = self.__private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Successfully decrypted message")

        # Split up the binary data to retrieve the file, signature and public key
        public_key = plaintext[:451]
        signature = plaintext[451:713]
        file = plaintext[713:]

        return public_key, signature, file

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=8192)
        public_key = private_key.public_key()

        self.__private_key = private_key
        self._public_key = public_key

        print("Successfully generated RSA encryption keys")

    def send_public_key(self):
        if not self.__private_key:
            print("No public key exists")
            return

        # Serialise key to PEM format
        key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self._conn[0].send(key_pem)

        print("Sent public encryption key to client")

    def verify_sig(self, file, sig, sig_key):
        # Verify the file's signature against its contents the client's public key

        # Serialise the signature public key received from the client
        key = serialization.load_pem_public_key(sig_key)

        # The TPM generated signature received from the client is in a different format
        # than what we need. We can truncate the first 6 bytes to format it correctly
        sig = sig[6:]

        # Run the verification
        try:
            key.verify(
                sig,
                file,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature of file is [\033[32mVALID\033[0m]")
            return True

        except InvalidSignature:
            print("Signature of file is [\033[31mINVALID\033[0m]")
            return False



if __name__ == '__main__':
    server = Server('127.0.0.1', 8120)
    server.send_public_key()
    sig_key, sig, file = server.receive_message()

    verified = server.verify_sig(file, sig, sig_key)

