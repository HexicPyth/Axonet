# Python 3.6.2

import socket
import struct
import threading

network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket()
terminated = False


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
    def append(sock, address):
        network_tuple[0].append(sock)
        network_tuple[1].append(address)

    def connect(self, in_socket, address, port, local=False):
        if local:
            print("Client -> Connecting to localhost server...", end='')
            in_socket.connect((address, port))
            print("success!")
            print("Client -> Connected.")

        if not local:
            print("Client -> Connecting to ", address, sep='')
            in_socket.connect((address, port))
            print("Client -> Success")
            self.send(in_socket, "echo")

    ''' The following thee functions were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield '''

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
            try:
                packet = (sock.recv(n - len(data))).decode()

            except OSError:
                print("Client -> Connection probably down or terminated (OSError: receiveall()")
                packet = None

            if not packet:
                return None
            else:
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

        if message == "stop":
            self.terminate()

    def listen(self, in_socket):
        def listener_thread(in_sock):
            while not terminated:
                incoming = self.receive(in_sock)
                message = incoming  # TODO: Implement hashing someday
                try:
                    if type(incoming):
                        print('Client -> Received: ' + message)
                        self.respond(in_sock, message)

                except OSError:
                    print("Client -> Connection probably down or terminated (OSError: listen() -> listener_thread())")
                except TypeError:
                    print("Client -> Connection probably down or terminated (TypeError: listen() -> listener_thread()")

        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(in_socket,), name='listener_thread').start()

    @staticmethod
    def terminate():
        global terminated
        print("Client -> Safely terminating our connections...")
        index = 0
        sock = network_tuple[0]
        addresses = network_tuple[1]

        for device in sock:
            print("Client -> Terminating connection to", addresses[index])
            device.close()
        terminated = True
        return 0

    def initialize(self, port=3704, network_architecture="Complete", remote_addresses=None):
        global localhost

        # Stage 0
        print("Client -> Initializing...")

        try:
            self.connect(localhost, 'localhost', port, local=True)
            self.append(localhost, 'localhost')

            print("Client -> Connection to localhost successful")
            print("Client -> Starting listener on localhost...")

            self.listen(localhost)

        except ConnectionRefusedError:
            print("Failed")
            print("Client -> Connection to local server was not successful; check that your server is "
                  "up, and try again later.")

        print("Client -> Attempting to connect to remote server... (Initiating stage 1)")
        # Stage 1
        if network_architecture == "Complete":
            if remote_addresses:
                for i in remote_addresses:
                    sock = socket.socket()
                    try:
                        self.connect(sock, i, port)
                        self.send(sock, "echo")
                    except ConnectionRefusedError:
                        print("Client -> Unable to connect to remove server; Failed to bootstrap.")
            else:
                print("Client -> Initializing with no remote connections...")
        else:
            print("TODO: Implement other network architectures")  # TODO: implement other architectures
