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
message_list = []
ballet_tuple = ([], [])

# Default parameters to be assigned by self.initialize() from init_client.init() (defaults are below)

PORT = 3705
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]
cluster_rep = None  # type -> bool
no_prop = "ffffffffffffffff"  # ffffffffffffffff:[message] = No message propagation.


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

    def disconnect(self, in_sock, disallow_local_disconnect=True):
        try:
            index = network_tuple[0].index(in_sock)  # Find the index of this socket so we can find it's address
            address = network_tuple[1][index]
            if disallow_local_disconnect:
                if address == self.get_local_ip():
                    return None
            else:
                print("\nDisconnecting from " + str(in_sock))
                print("Disconnecting from ", network_tuple[1][index])
                print("Client -> Removing " + str(in_sock) + " from network_tuple\n")
                network_tuple[0].pop(index)
                network_tuple[1].pop(index)
                in_sock.close()
                print("Client -> Successfully disconnected.")

        except (IndexError, ValueError):
            print("Already disconnected; passing")
            pass

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
        try:
            sock.sendall(msg)
        except OSError:
            self.disconnect(sock)

    def receiveall(self, sock, n):
        # Helper function to receive n bytes or return None if EOF is hit
        data = ''
        while len(data) < n:
            try:
                packet = (sock.recv(n - len(data))).decode()

            except OSError:
                print("Client -> Connection probably down or terminated (OSError: receiveall()")
                print("Client -> Disconnecting from "+str(sock))
                try:
                    self.disconnect(sock)
                except ValueError:
                    packet = None
                    raise ValueError
                raise ValueError

            except UnicodeDecodeError:
                packet = (sock.recv(n - len(data))).decode('utf-8', 'ignore')
                print(packet)

            if not packet:
                return None
            else:
                data += packet
        return data.encode()

    def receive(self, in_sock):
        # Read message length and unpack it into an integer
        try:
            raw_msglen = self.receiveall(in_sock, 4)

            if not raw_msglen:
                return None

            msglen = struct.unpack('>I', raw_msglen)[0]
            return self.receiveall(in_sock, msglen).decode()
        except ValueError:
            return 1

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
            if sig != no_prop:
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

            if message.startswith("ConnectTo:"):
                address = message[10:]
                if address not in network_tuple[1]:

                    if address == self.get_local_ip() or address == "127.0.0.1":
                        print("Not connecting to", address + ";", "That's localhost :P")

                    else:
                        sock = socket.socket()
                        self.connect(sock, address, PORT)
                        self.listen(sock)
                else:
                    print("\n\n"+str(network_tuple)+"\n\n")
                    print("Not connecting to", address+";", "We're already connected.")

            if message.startswith('exec:'):
                if allow_command_execution:
                    command = message[5:]
                    print("executing: "+command)
                    # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                    # non-isolated fork of a process. Use as your own risk, and please secure your subnet.
                    command_process = multiprocessing.Process(target=self.run_external_command,
                                                              args=(command,), name='Cmd_Thread')
                    command_process.start()

                else:

                    print("Not executing command: ", message[5:])

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

            if message.startswith('elect:'):
                print("\n"+str(network_tuple)+"\n")
                info = message[6:]
                number = info[-16:]
                address = info[:-17]
                print(number, address)
                ballet_tuple[0].append(number)
                ballet_tuple[1].append(address)

                if len(ballet_tuple[0]) == len(network_tuple[0]) and len(ballet_tuple[0]) != 0:
                    int_ballet_tuple = [int(i) for i in ballet_tuple[0]]

                    index = int_ballet_tuple.index(max(int_ballet_tuple))
                    print("\n--- " + ballet_tuple[0][index])   # we actually want the string here, not the int.
                    print("--- " + ballet_tuple[1][index] + " won the election for cluster representative\n")
                    cluster_rep = ballet_tuple[1][index]

            if message.startswith("file:"):
                info = message[5:]
                file_hash = info[:16]
                file_length = info[-4:]
                print("\n Client -> Store segment of file: "+file_hash+" of length:"+file_length+"?")

            if message.startswith("remove:"):

                address_to_remove = message[7:]

                try:
                    if address_to_remove != self.get_local_ip() and address_to_remove != "127.0.0.1":
                        print("Client -> remove -> Disconnecting from " + address_to_remove)
                        index = network_tuple[1].index(address_to_remove)
                        sock = network_tuple[0][index]
                        print('\n', address_to_remove, '=', sock, '\n')

                        network_tuple[0].pop(index)
                        network_tuple[1].pop(index)  # self.disconnect() has an attitude again...
                        sock.close()

                    else:
                        print("Client -> Not disconnecting from localhost, dimwit.")

                except ValueError:  # (ValueError, TypeError)
                    print("Server -> Sorry, we're not connected to " + address_to_remove)
                    pass

            # End of respond()
            print('Client -> broadcasting: '+full_message)
            self.broadcast(full_message)

    def listen(self, in_socket):
        def listener_thread(in_sock):
            global terminated
            while not terminated:
                incoming = self.receive(in_sock)
                msg = incoming
                try:
                    if incoming:
                        self.respond(in_sock, msg)

                except TypeError:
                    print(in_sock)
                    print("Client -> Connection probably down or terminated (TypeError: listen() -> listener_thread()")
                    self.disconnect(in_sock)
                    terminated = True
                if incoming == 1:
                    print("Connection to " + str(in_sock) + "doesn't exist, terminating listener_thread()")
                    terminated = True
        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(in_socket,), name='listener_thread').start()

    def terminate(self):
        global terminated
        print("Client -> Safely terminating our connections...")
        index = 0
        sock = network_tuple[0]
        addresses = network_tuple[1]

        for device in sock:
            print("Client -> Terminating connection to", addresses[index])
            self.disconnect(device, disallow_local_disconnect=False)
            index += 1
        terminated = True
        return 0

    def initialize(self, port=3705, network_architecture="Complete", remote_addresses=None,
                   command_execution=False):
        global allow_command_execution
        global localhost
        global PORT

        PORT = port  # Global variable assignment
        allow_command_execution = command_execution

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
