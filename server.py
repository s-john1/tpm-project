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

        return data

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

    def write_file(self, data, name):
        # Write the file to the given location
        with open(name, "wb") as f:
            f.write(data)

        print(f"File written to {name}")

    def verify_pcr(self, file, pcr_value):
        # Verify the PCR value from the client matches the hash value we calculate from the file

        # First generate the SHA256 hash of the file
        h = hashes.Hash(hashes.SHA256())
        h.update(file)
        file_hash = h.finalize()

        # Next, we need to hash the file's hash with padded zeros to match the behaviour of the TPM's PCR
        h = hashes.Hash(hashes.SHA256())
        h.update(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'+file_hash)
        final_hash = h.finalize()

        # Check if the calculated hash matches the hash from the PCR
        if final_hash == pcr_value:
            print("PCR value from client is [\033[32mVALID\033[0m]")
            return True
        else:
            print("PCR value from client is [\033[31mINVALID\033[0m]")
            return False

    def decrypt_message(self, message):
        try:
            plaintext = self.__private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Encryption of file is [\033[32mVALID\033[0m]")
        except:
            print("Encryption of file is [\033[31mINVALID\033[0m]")
            return False

        # Split up the binary data to retrieve the file, signature, PCR and public key
        public_key = plaintext[:451]
        signature = plaintext[451:713]
        pcr_value = plaintext[713:745]
        file = plaintext[745:]

        return public_key, signature, pcr_value, file


    def check_file_integrity(self, enc_message):
        result = self.decrypt_message(enc_message)
        if result:
            sig_key, sig, pcr_val, file = result

            sig_verified = self.verify_sig(file, sig, sig_key)
            pcr_verified = self.verify_pcr(file, pcr_val)

            if sig_verified and pcr_verified:
                server.write_file(file, "output.txt")
                print("\033[32mFile from client passed integrity checks!\033[0m")
                return

        print("\033[31mFile from client has failed integrity checks.\033[0m")


if __name__ == '__main__':
    server = Server('127.0.0.1', 8120)
    server.send_public_key()
    encrypted_message = server.receive_message()
    server.check_file_integrity(encrypted_message)
