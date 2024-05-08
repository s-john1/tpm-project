import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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

    def receive_file(self, filename):
        f = open(filename, 'wb')

        data = self._conn[0].recv(1024)
        while data:
            if not data:
                return

            f.write(data)
            data = self._conn[0].recv(1024)

        print("Received file")

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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



if __name__ == '__main__':
    server = Server('127.0.0.1', 8120)
    server.send_public_key()
    #server.receive_file("output")
