import socket
import struct
import threading

# Python 3.6.2
network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket()


class Client:
    # Find our local IP address and return it as a string
    @staticmethod
    def get_local_ip():

        # Creates a temporary socket and connects to subnet, yielding our local IP address.
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            temp_socket.connect(('10.255.255.0', 0))
            local_ip = temp_socket.getsockname()[0]

        except OSError:
            # Connect refused; there is likely no network connection.
            local_ip = "127.0.0.1"

        finally:
            temp_socket.close()

        return local_ip

    @staticmethod
    def connect(in_socket, address, port, local=False):
        if local:
            print("Client -> Connecting to localhost server...", end='')

        if not local:
            print("Client -> Connecting to ", address, sep='')

        in_socket.connect((address, port))
        print("success!")
        print("Client -> Connected.")

    @staticmethod
    def send(in_socket, message):
        msg = message.encode('utf-8')
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        in_socket.sendall(msg)

    @staticmethod
    def receiveall(sock, n):
        # Helper function to receive n bytes or return None if EOF is hit
        data = ''
        while len(data) < n:
            packet = (sock.recv(n - len(data))).decode()
            if not packet:
                return None
            data += packet
        return data.encode()

    def receive(self, in_sock):
        # Read message length and unpack it into an integer
        raw_msglen = self.receiveall(in_sock, 4)

        if not raw_msglen:
            return None

        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.receiveall(in_sock, msglen).decode()

    def respond(self, in_sock, message):
        if message == "echo":
            # Check if Client/Server communication is intact
            print("Client -> echoing...")
            self.send(in_sock, message)  # If received, send back

    def listen(self, in_socket):
        def listener_thread(in_sock):
            while 1:
                incoming = self.receive(in_sock)
                message = incoming  # TODO: Implement hashing someday
                try:
                    if type(incoming):
                        print('Client -> Received: ' + message)
                        self.respond(in_sock, message)

                except OSError:
                    pass

        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(in_socket,), name='listener_thread').start()

    def terminate(self):
        pass

    def initialize(self, port=3704):
        global localhost

        print("Client -> Initializing...")

        try:
            self.connect(localhost, 'localhost', port, local=True)
            print("Client -> Starting listener on localhost...")

            self.listen(localhost)

        except ConnectionRefusedError:
            print("Failed")
            print("Client -> Connection to local server was not successful; check that your server is "
                  "up, and try again later.")


x = Client()
x.initialize(port=3705)
