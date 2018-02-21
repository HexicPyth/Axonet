# Python 3.6.2
import socket
import struct
import inject
import threading
from hashlib import sha3_224
import datetime

# Globals
network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Add SO_REUSEADDR
injector = inject.NetworkInjector()
message_list = []   # List of message hashes
no_prop = "ffffffffffffffff"  # Sending a message with a true hash indicates that no message propagation is needed.
net_injection = False
injector_terminated = False


class Server:
    @staticmethod
    def get_local_ip():
        # Creates a temporary socket and connects to subnet, yielding our local address.
        # Returns: (local ip address) -> str
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
    def prepare(message):
        # Assign unique hashes to messages for transport
        # Returns: (hash+message) -> str
        # Please excuse the mess :P

        out = ""
        timestamp = str(datetime.datetime.utcnow())
        out += timestamp
        out += message
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = ""
        out += sig
        out += ":"
        out += message
        return out

    ''' The three functions below were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield '''

    def send(self, sock, message, signing=True):
        if signing:
            msg = self.prepare(message).encode('utf-8')
        else:
            msg = message.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        try:
            sock.sendall(msg)
        except BrokenPipeError:
            index = network_tuple[0].index(sock)
            address = network_tuple[1][index]
            print("Server -> Something happened sending to "+address)
            print("Server -> Disconnecting from "+address)

            network_tuple[0].pop(index)
            network_tuple[1].pop(index)  # self.disconnect() doesn't like broken sockets
            sock.shutdown()
            sock.close()

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
        # Returns: (message) -> str

        raw_msglen = self.receiveall(in_sock, 4)

        if not raw_msglen:
            return None

        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.receiveall(in_sock, msglen).decode()

    def broadcast(self, message):
        sockets = network_tuple[0]  # List of client we need to broadcast to
        for client in sockets:
            index = network_tuple[0].index(client)
            address = network_tuple[1][index]
            print("Server -> Sending to: "+address)
            self.send(client, message, signing=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def append(in_socket, address):
        # Add single address/socket tuple to the (global) network tuple.
        global network_tuple  # (sockets, addresses)

        network_tuple[0].append(in_socket)  # Append socket to network tuple
        network_tuple[1].append(address)  # Append address to network tuple

    def stop(self):
        # Try to gracefully disconnect & disassociate from the network
        print("Client -> stop() -> Trying to gracefully disconnect and disassociate.")

        for connection in network_tuple[0]:
            print("Trying to disconnect from socket: " + str(connection))
            try:
                self.disconnect(connection, disallow_local_disconnect=True)
                print("Successfully disconnected")
            except OSError:
                print("Failed to disconnect from socket: "+str(connection))
        localhost.close()
        quit(0)

    def respond(self, msg, in_sock):
        global no_prop
        global message_list
        full_message = str(msg)
        sig = msg[:16]
        if sig not in message_list:
            print('Server -> Received: ' + msg)

            message = msg[17:]
            index = network_tuple[0].index(in_sock)
            address = network_tuple[1][index]
            if message == "echo":
                # If received, we can two-way communication is functional
                print("Server -> Note: Two-Way communication with", address, "established and/or tested functional")
                self.send(in_sock, no_prop+":continue", signing=False)

            if sig not in message_list and sig != no_prop:
                message_list.append(sig)
                print("Server -> Broadcasting "+full_message)
                self.broadcast(full_message)

    def disconnect(self, in_sock, disallow_local_disconnect=True):
        try:
            index = network_tuple[0].index(in_sock)  # Find the index of this socket so we can find it's address
            address = network_tuple[1][index]
            if disallow_local_disconnect:
                if address == self.get_local_ip():
                    print("Client -> BUG -> Refusing to disconnect from localhost; that's a terrible idea.")
                    return None
            else:
                print("\nDisconnecting from " + str(in_sock))
                print("Disconnecting from ", network_tuple[1][index])
                print("Client -> Removing " + str(in_sock) + " from network_tuple\n")
                network_tuple[0].pop(index)
                network_tuple[1].pop(index)
                in_sock.close()
                print("Client -> Successfully disconnected.")

        except IndexError:
            print("Already disconnected; passing")
            pass

    def listen(self, in_sock):
        global injector_terminated

        def listener():
            listener_terminated = False  # When set, this thread and this thread only, is stopped.

            while not listener_terminated:
                try:
                    incoming = self.receive(in_sock)
                    if incoming:
                        self.respond(incoming, in_sock)

                except (OSError, TypeError):
                    print(str(in_sock))
                    index = network_tuple[0].index(in_sock)
                    address = network_tuple[1][index]
                    print(address)

                    if address == self.get_local_ip() or address == "127.0.0.1":
                        print("Server -> Something happened with localhost; not disconnecting")
                    else:
                        try:
                            self.disconnect(in_sock)
                        except ValueError:
                            print("Server -> Socket closed")
                        finally:
                            print("Server -> Connection to "+str(in_sock) + "probably down or terminated;")
                            listener_terminated = True

        def start_injector(client):
            global net_injection
            global injector_terminated

            if not injector_terminated:
                if net_injection:
                    x = injector.init(network_tuple)

                    # The mess below handles the collect() loop that would normally be in inject.py
                    net_len = len(network_tuple[0])
                    while 1:
                        nl = len(network_tuple[0])
                        if net_len != nl:
                            break
                        print(x)
                        if type(x) == str:
                            print("\n TODO: Server -> Disconnect from: " + x)
                            index = network_tuple[1].index(x)
                            print(network_tuple)
                            sock = network_tuple[0][index]
                            self.disconnect(sock)

                        if x == 0 and len(network_tuple[0]) >= 1:
                            try:
                                print(network_tuple)
                                x = injector.init(network_tuple)
                            except BrokenPipeError:
                                pass  # We'll get the address of the disconnected device shortly; pass

                        elif len(network_tuple[0]) == 0:
                            break

                        elif len(network_tuple[0]) > 1 or len(network_tuple[0]) != net_len:
                            print("!!!")
                            break  # We have remote connections...
                        else:
                            break
            elif injector_terminated:
                print("Terminating Injector...")
                return 0

        # Start listener in a new thread
        print('starting listener thread')
        threading.Thread(target=listener, name='listener_thread').start()

        injector_terminated = True  # Kill any running network injector(s)
        injector_terminated = False

        threading.Thread(target=start_injector, name='injector_thread', args=(in_sock,)).start()

    def initialize(self, port=3704, listening=True, method="socket", network_injection=False,
                   network_architecture="complete"):
        if method == "socket":
            global injector
            global localhost
            global net_injection
            address_string = self.get_local_ip()+":"+str(port)
            net_injection = network_injection

            print("Server -> Initializing...")

            print("Server -> Binding server on: ", address_string, "...", sep='')

            try:
                localhost.bind(('', port))
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

                    else:  # this is a remote connection
                        print("Server -> ", address, " has connected.", sep='')
                        print("Server -> Listening on ", address, sep='')
                        self.listen(client)
                        self.send(client, "echo")

                    if network_architecture == "complete":
                        print("!")
                        self.broadcast(self.prepare('ConnectTo:' + address))
                        print('...')

                except ConnectionResetError:
                    print("Server -> localhost has disconnected")

        else:
            print("TODO: implement other protocols")  # TODO: Implement other protocols
