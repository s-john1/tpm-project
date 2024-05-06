import socket


class Client:
    _sock = None

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




if __name__ == "__main__":
    client = Client("127.0.0.1", 8120)
    client.send_file("text.txt")
