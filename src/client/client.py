# Python 3.6.2

import socket
import struct
import threading
import multiprocessing
import datetime
import os
import random
from hashlib import sha3_224

network_tuple = ([], [])  # (sockets, addresses)
localhost = socket.socket()
terminated = False
PORT = 1111  # This will be re-defined on initialization; It's temporary
message_list = []
ballet_tuple = ([], [])

# ffffffffffffffff:[message] (i.e a message with a True hash) indicates that no propagation is required.
no_prop = "ffffffffffffffff"
cluster_rep = None  # type -> str


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
            self.append(in_socket, address)
            print("success!")
            print("Client -> Connected.")

        if not local:
            print("Client -> Connecting to ", address, sep='')
            in_socket.connect((address, port))
            self.append(in_socket, address)
            print("Client -> Success")

    @staticmethod
    def prepare(message):  # Process our message for broadcasting (Please ignore the mess :P)
        out = ""
        timestamp = str(datetime.datetime.utcnow())
        out += timestamp
        out += message
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = sig+":"+message
        return out

    ''' The following thee functions were written by StackOverflow user 
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

    def broadcast(self, message):
        sockets = network_tuple[0]  # List of client we need to broadcast to
        for server in sockets:
            self.send(server, message, signing=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def run_external_command(command):  # Important: To be run in external thread/process only!!!!
        os.system(command)
        return 0

    def respond(self, in_sock, msg):
        global message_list
        global ballet_tuple
        global cluster_rep

        full_message = str(msg)
        sig = msg[:16]
        message = msg[17:]
        if sig in message_list:
            print("Client -> Not responding to "+sig)
        else:
            message_list.append(sig)  # Note this location. Race conditions occur if this is placed later-on...
            index = network_tuple[0].index(in_sock)
            address = network_tuple[1][index]  # Find the address of the socket we're receiving from...
            print('Client -> Received: ' + message + " (" + sig + ")" + "from: " + address)

            if message == "echo":
                # Check if Client/Server communication is intact
                print("Client -> echoing...")
                self.send(in_sock, no_prop+':'+message, signing=False)  # If received, send back

            if message == "stop":
                self.terminate()

            if message[:10] == "ConnectTo:":
                address = message[10:]
                if address not in network_tuple[1]:

                    if address == self.get_local_ip():
                        print("Not connecting to", address + ";", "That's localhost :P")

                    else:
                        sock = socket.socket()
                        self.connect(sock, address, PORT)
                        self.listen(sock)
                else:
                    print("Not connecting to", address+";", "We're already connected.")

            if message[:5] == "exec:":
                command = message[5:]
                print("executing: "+command)
                # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                # non-isolated fork of a process. Use as your own risk, and please secure your subnet.
                command_process = multiprocessing.Process(target=self.run_external_command,
                                                          args=(command,), name='Cmd_Thread')
                command_process.start()

            if message == "vote":
                ballet_tuple = ([], [])  # Clear the ballet before initiating the vote
                elect_msg = "elect:"

                uid_str = ""  # <-- Will be a random 16-digit number(zeroes included)
                for i in range(0, 16):
                    uid_str += str(random.SystemRandom().randint(0, 9))

                while len(uid_str) != 16:  # Make sure that uid_str is <i>really</i> a 16-digit integer
                    uid_str = uid_str[:-1]

                elect_msg += self.get_local_ip()
                elect_msg += ":"
                elect_msg += uid_str
                print(len(uid_str))
                print("Contributing to the election: "+elect_msg)
                self.broadcast(self.prepare(elect_msg))
                del elect_msg

            if message[:6] == "elect:":
                info = message[6:]
                number = info[-16:]
                address = info[:-17]
                print(number, address)
                ballet_tuple[0].append(number)
                ballet_tuple[1].append(address)

                print(len(ballet_tuple[0]))
                print(len(network_tuple[0]))
                print(ballet_tuple)

                if len(ballet_tuple[0]) == len(network_tuple[0]) and len(ballet_tuple[0]) != 0:
                    int_ballet_tuple = [int(i) for i in ballet_tuple[0]]

                    index = int_ballet_tuple.index(max(int_ballet_tuple))
                    print("--- " + ballet_tuple[0][index])   # we actually want the string here, not the int.
                    print("--- " + ballet_tuple[1][index] + " won the election for cluster representative")
                    cluster_rep = ballet_tuple[1][index]

            # End of respond()
            print('Client -> broadcasting: '+full_message)
            self.broadcast(full_message)

    def listen(self, in_socket):
        def listener_thread(in_sock):
            while not terminated:
                incoming = self.receive(in_sock)
                msg = incoming
                try:
                    if incoming:
                        self.respond(in_sock, msg)

                #except OSError:
                #    print("Client -> Connection probably down or terminated (OSError: listen() -> listener_thread())")
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
            index += 1
        terminated = True
        return 0

    def initialize(self, port=3704, network_architecture="Complete", remote_addresses=None):
        global localhost
        global PORT
        PORT = port
        # Stage 0
        print("Client -> Initializing...")

        try:
            self.connect(localhost, 'localhost', port, local=True)

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

                        print("Starting listener on", i)
                        self.listen(sock)

                        self.send(sock, "echo")
                    except ConnectionRefusedError:
                        print("Client -> Unable to connect to remove server; Failed to bootstrap.")
            else:
                print("Client -> Initializing with no remote connections...")
        else:
            print("TODO: Implement other network architectures")  # TODO: implement other architectures
