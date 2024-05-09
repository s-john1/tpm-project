import os
import socket
import subprocess

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class Client:
    _sock = None
    _server_public_key = None

    __private_key = None
    _public_key = None

    _TSS_DIR = "utils"
    _TEMP_DIR = "/tmp/tpm-client"

    def __init__(self, address, port):
        self._address = address
        self._port = port

        self._connect()
        self._setup_tpm()

        # Create temporary working directory
        os.makedirs(self._TEMP_DIR, exist_ok=True)

    def _connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._address, self._port))
        print(f"Connected to {self._address}:{self._port}")

    def _setup_tpm(self):
        print("Setting up TPM:")
        subprocess.run("./pcrreset -ha 16", shell=True, cwd=self._TSS_DIR)
        subprocess.run("./flushcontext -ha 80000000", shell=True, cwd=self._TSS_DIR)
        subprocess.run("./flushcontext -ha 80000001", shell=True, cwd=self._TSS_DIR)
        subprocess.run("./createprimary -hi o", shell=True, cwd=self._TSS_DIR)
        print("TPM is setup")

    def send_message(self, message):
        self._sock.sendall(message)

        print("Finished sending message server")

    def receive_public_key(self):
        # Receive the server's public encryption key
        data = self._sock.recv(4096)

        if not data:
            print("Unable to receive public key from the server")
            return

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
        dir = self._TEMP_DIR

        if not self.__private_key:
            print("Can't load private key to TPM")
            return

        pem = self.__private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Export private key
        with open(dir+"/private.pem", "wb") as keyfile:
            keyfile.write(pem)
        print("Exported public and private keys")

        # Import the private key to the TPM
        subprocess.run(f"./importpem -hp 80000000 -ipem {dir}/private.pem -rsa -si -opu {dir}/pub.bin -opr {dir}/priv.bin",
                       shell=True, cwd=self._TSS_DIR)
        subprocess.run(f"./load -hp 80000000 -ipu {dir}/pub.bin -ipr {dir}/priv.bin",
                       shell=True, cwd=self._TSS_DIR)
        print("TPM has imported the private key")

        # Cleanup local files and variables
        os.remove(dir+"/private.pem")
        os.remove(dir+"/pub.bin")
        os.remove(dir+"/priv.bin")
        del self.__private_key

    def sign_file(self, file):
        # Use the TPM to sign the file and then retrieve the signature
        subprocess.run(f"./sign -hk 80000001 -if ../{file} -halg sha256 -os {self._TEMP_DIR}/sig.bin",
                       shell=True, cwd=self._TSS_DIR)

        with open(self._TEMP_DIR+"/sig.bin", "rb") as f:
            signature = f.read()

        print(f"Created signature on file {file}")
        return signature

    def extend_pcr(self, file):
        # Add the hash of the file to the TPM's PCR, and then read the current PCR value

        # Generate SHA256 hash of the file and save to /tmp
        subprocess.run(f"openssl dgst -sha256 -binary < {file} > {self._TEMP_DIR}/hash.bin", shell=True)

        # Use TPM to extend the PCR with the hash of the file
        subprocess.run(f"./pcrextend -ha 16 -if {self._TEMP_DIR}/hash.bin", shell=True, cwd=self._TSS_DIR)

        # Remove temporary hash file
        os.remove(self._TEMP_DIR+"/hash.bin")

        # Get the current value of the PCR
        output = subprocess.check_output("./pcrread -ha 16 -ns", shell=True, cwd=self._TSS_DIR)

        # Remove newline break from return value
        output = output[:-1]

        # Format to binary
        pcr = bytes.fromhex(output.decode())

        return pcr

    def encrypt_file(self, file, signature, pcr_value):
        # Package the file with its signature and public key, then encrypt it
        data = self._public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Append the signature and PCR value to our data
        data += signature + pcr_value

        # Open file and append its contents to our data
        with open(file, "rb") as f:
            file_data = f.read()
        data += file_data

        # Encrypt our data object with the server's public key
        ciphertext = self._server_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext


if __name__ == "__main__":
    file = "text.txt"

    client = Client("127.0.0.1", 8120)
    client.receive_public_key()

    client.generate_signing_keys()
    client.tpm_load_key()

    sig = client.sign_file(file)
    pcr = client.extend_pcr(file)
    enc = client.encrypt_file(file, sig, pcr)
    client.send_message(enc)