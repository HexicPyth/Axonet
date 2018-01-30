# Python 3.6.2
import socket
import struct
import inject
import threading
from hashlib import sha3_224
import datetime

network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Add SO_REUSEADDR
injector = inject.NetworkInjector()
message_list = []
no_prop = "ffffffffffffffff"


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
    def prepare(message):  # Process our message for broadcasting
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

    def broadcast(self, message):
        sockets = network_tuple[0]  # List of client we need to broadcast to
        for client in sockets:
            self.send(client, message, signing=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def append(in_socket, address):
        global network_tuple  # (sockets, addresses)

        network_tuple[0].append(in_socket)  # Append socket to network tuple
        network_tuple[1].append(address)  # Append address to network tuple

    @staticmethod
    def stop():
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

                print("Broadcasting: "+full_message)
                self.broadcast(full_message)
                message_list.append(sig)
            if sig == no_prop:
                print("Server -> Info: Not propagating: " + message + " (sig = "+no_prop+')"')

    @staticmethod
    def disconnect(in_sock):
        index = network_tuple[0].index(in_sock)  # Find the index of this socket so we can find it's address
        print("Disconnecting from ", network_tuple[1][index])
        in_sock.close()

        print("Server -> Removing from network_tuple")
        network_tuple[0].pop(index)
        network_tuple[1].pop(index)

        print("Server -> Successfully disconnected.")

    def listen(self, in_sock):
        def listener():
            listener_terminated = False  # When set, this thread and this thread only, is stopped.

            while not listener_terminated:
                incoming = self.receive(in_sock)
                try:
                    if incoming:
                        self.respond(incoming, in_sock)
                except OSError:
                    pass
                except TypeError:
                    print("Server -> Connection probably down or terminated; Disconnecting...")
                    self.disconnect(in_sock)
                    listener_terminated = True

        # Start listener in a new thread
        print('starting listener thread')
        threading.Thread(target=listener, name='listener_thread').start()

    def initialize(self, port=3704, listening=True, method="socket", network_injection=False,
                   network_architecture="complete"):
        if method == "socket":
            global injector
            global localhost
            address_string = self.get_local_ip()+":"+str(port)

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

                        if network_injection:
                            try:
                                injector.kill()  # Let's make sure this doesn't run in multiple processes
                            except AttributeError:
                                pass
                            finally:
                                injector.init(network_tuple)

                    else:  # this is a remote connection
                        print("Server -> ", address, " has connected.", sep='')
                        print("Server -> Listening on ", address, sep='')
                        self.listen(client)
                        self.send(client, "echo")

                        if network_injection:
                            try:
                                injector.kill()  # Let's make sure this doesn't run in multiple processes
                            except AttributeError:
                                pass
                            finally:
                                injector.init(network_tuple)

                        if network_architecture == "complete":
                            self.broadcast(self.prepare('ConnectTo:'+address))
                            print('...')
                except ConnectionResetError:
                    print("Server -> localhost has disconnected")

        else:
            print("TODO: implement other protocols")  # TODO: Implement other protocols
