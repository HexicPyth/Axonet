import socket
import struct
import threading

network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TODO: add SO_REUSEADDR


class Server:
    @staticmethod
    def get_local_ip():

        # Creates a temporary socket and connects to subnet, yielding our local address.
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            temp_socket.connect(('10.255.255.0', 0))

            # Yield our local address
            local_ip = temp_socket.getsockname()[0]

        except OSError:
            # Connect refused; there is likely no network connection.
            print("Server -> get_local_ip() -> No network connection detected.")
            local_ip = "127.0.0.1"

        finally:
            temp_socket.close()

        return local_ip

    @staticmethod
    def send(sock, msg):
        msg = msg.encode('utf-8')  # TODO: implement hashing someday
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        sock.sendall(msg)

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

    @staticmethod
    def append(in_socket, address):
        global network_tuple  # (sockets, addresses)

        network_tuple[0].append(in_socket)  # Append socket to network tuple
        network_tuple[1].append(address)  # Append address to network tuple

    @staticmethod
    def stop():
        localhost.close()
        quit(0)

    @staticmethod
    def respond(message, in_sock):
        message = message  # TODO: implement hashing someday.
        if message == "echo":
            # If received, we can two-way communication is functional
            print("Server -> Note: Two-Way communication established and tested functional")

    def listen(self, in_sock):
        def listener():
            while 1:
                incoming = self.receive(in_sock)
                try:
                    if type(incoming):
                        print('Server -> Received: ' + incoming)
                        self.respond(incoming, in_sock)
                except OSError:
                    pass

        # Start listener in a new thread
        print('starting listener thread')
        threading.Thread(target=listener, name='listener_thread').start()

    def initialize(self, port=3704, listening=True, method="socket"):
        if method == "socket":
            global localhost
            address_string = self.get_local_ip()+":"+str(port)

            print("Server -> Initializing...")

            print("Server -> Binding server on: ", address_string, "...", sep='')

            try:
                localhost.bind(('127.0.0.1', port))
                print(" success!")
            except OSError:
                print(" failed!")
                print("Failed to bind server on", address_string, "Please try again later.")
                self.stop()

            print("Server -> Server successfully bound on: ", address_string, sep='')

            if listening:
                print("Server -> Now Listening for incoming connections...")

            while listening:  # Listening... (for connections)
                try:
                    localhost.listen(5)
                    client, address_tuple = localhost.accept()
                    address = address_tuple[0]
                    self.append(client, address)

                    if address == "127.0.0.1":
                        print("Server -> localhost has connected.")
                        self.send(client, "echo")
                        self.listen(client)
                        print("Server -> Listening on localhost...")

                    else:
                        print("Server -> ", address, " has connected.", sep='')
                        print("Server -> Listening on ", address, sep='')
                        self.listen(client)

                except ConnectionResetError:
                    print("Server -> localhost has disconnected")

        else:
            print("TODO: implement other protocols")  # TODO: Implement other protocols


x = Server()
x.initialize(port=3705, method="socket", listening=True)
