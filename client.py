import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class Client:
    _sock = None
    _server_public_key = None

    __private_key = None
    _public_key = None

    def __init__(self, address, port):
        self._address = address
        self._port = port

        self._connect()

    def _connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._address, self._port))
        print(f"Connected to {self._address}:{self._port}")

    def send_file(self, filename):
        f = open(filename, 'rb')

        data = f.read()
        if not data:
            return

        self._sock.sendall(data)

        print(f"Finished sending file {filename}")

    def receive_public_key(self):
        # Receive the server's public encryption key
        data = self._sock.recv(1024)

        if not data:
            print("Unable to receive public key from the server")
            return

        print(data.decode("utf-8"))

        # Deserialise the public key
        key = load_pem_public_key(data)
        self._server_public_key = key

    def generate_signing_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        self.__private_key = private_key
        self._public_key = public_key

        print("Successfully generated RSA signing keys")

    def tpm_load_key(self):
        if not self.__private_key:
            print("Can't load private key to TPM")
            return

        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private.pem", "wb") as keyfile:
            keyfile.write(pem)

        # TODO: delete local pem
        # TODO: delete variables


if __name__ == "__main__":
    client = Client("127.0.0.1", 8120)
    client.receive_public_key()
    #client.send_file("text.txt")
