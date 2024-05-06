import socket


class Server:
    _sock = None
    _conn = None

    def __init__(self, listen_addr, port):
        self.listen_addr = listen_addr
        self.port = port

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


if __name__ == '__main__':
    server = Server('127.0.0.1', 8120)
    server.receive_file("output")
