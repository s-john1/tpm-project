import socket

class Server:
    _sock = None

    def __init__(self, listen_addr, port):
        self.listen_addr = listen_addr
        self.port = port

        # Create TCP socket
        self.create_listener()

    def create_listener(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((self.listen_addr, self.port))
        self._sock.listen()
        print(f"Server listening on {self.listen_addr}:{self.port}")




if __name__ == '__main__':
    server = Server('127.0.0.1', 8120)