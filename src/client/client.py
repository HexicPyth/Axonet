# Python 3.6.2
import socket
import struct
import threading
import multiprocessing
import datetime
import os
import random
from hashlib import sha3_224

# Globals
localhost = socket.socket()
PORT = 3705
network_tuple = ()  # (socket, address)
ballet_tuple = ([], [])  # (value, address)
message_list = []

cluster_rep = None  # type -> bool
terminated = False  # If true: the client has instructed to terminate; inform our functions and exit cleanly.
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]

no_prop = "ffffffffffffffff"  # ffffffffffffffff:[message] = No message propagation.


class Client:

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
        # Assign unique hashes to messages ready for transport.
        # Returns (new hashed message) -> str
        out = ""
        timestamp = str(datetime.datetime.utcnow())
        out += timestamp
        out += message
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = sig+":"+message
        return out

    @staticmethod
    def lookup_socket(address):  # TODO: optimize me
        for item in network_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

    @staticmethod
    def lookup_address(in_sock):  # TODO: optimize me
        for item in network_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

    @staticmethod
    # Add a connection to the network_tuple
    def append(in_socket, address):
        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        connection = (in_socket, address)
        network_list.append(connection)

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    @staticmethod
    # Remove a connection from the network_tuple
    def remove(connection):
        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        # Identify and remove said connection
        try:
            index = network_list.index(connection)
            network_list.pop(index)

        # Connection not in network tuple, or socket is [closed]
        except ValueError:
            print("Client -> Not removing non-existent connection: "+connection)
            return None

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def connect(self, connection, address, port, local=False):
        # Connect to a remote server and handle the connection(i.e append it).
        # Returns nothing.
        sock = connection[0]
        if connection in network_tuple:
            print("Client -> Not connection to "+connection[1], "We're already connected.")

        else:

            if local:
                print("Client -> Connecting to localhost server...", end='')
                sock.connect((address, port))
                self.append(sock, address)
                print("success!")
                print("Client -> Connected.")

            if not local:
                print("Client -> Connecting to ", address, sep='')
                sock.connect((address, port))
                self.append(sock, address)
                print("Client -> Success")

    def disconnect(self, connection, disallow_local_disconnect=True):
        # Try to disconnect from a remote server and remove it from the network tuple.
        # Returns None if you try to do something stupid. otherwise returns nothing at all.

        try:
            sock = connection[0]
            address = connection[1]
        except TypeError:
            print("Warning: Expected a connection tuple, got something else... Returning..."
                  "(TypeError -> self.disconnect())")
            return None

        try:
            # Don't disconnect from localhost. That's done with self.terminate().
            if disallow_local_disconnect:

                if address == self.get_local_ip() or address == "127.0.0.1":
                    return None

            # Do disconnect from remote nodes. That actually makes sense.
            else:
                print("\nDisconnecting from " + str(sock))  # Print the socket we're disconnecting from
                print("Disconnecting from ", address)  # Print the address we're disconnecting from

                self.remove(connection)

                try:
                    sock.close()

                except OSError:
                    print("Failed to close the socket of "+address + " -> OSError -> self.disconnect()")

                finally:
                    print("Client -> Successfully disconnected.")

        # Either the socket in question doesn't exist, or  the socket is probably [closed].
        except (IndexError, ValueError):
            print("Already disconnected; passing")
            pass

    ''' The following thee functions were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield '''

    def send(self, connection, message, signing=True):
        # Helper function to encode a given message and send it to a given server.
        # Returns nothing.
        sock = connection[0]

        if signing:
            msg = self.prepare(message).encode('utf-8')
        else:
            msg = message.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg

        # Attempt to send the message through normal means.
        try:
            sock.sendall(msg)

        # Socket probably disconnected, let's do the same and remove it
        # from the network tuple so it can't cause issues.
        except OSError:
            self.disconnect(connection)

    @staticmethod
    def receiveall(sock, n):
        # Helper function to receive n bytes.
        # returns None if EOF is hit

        data = ''

        while len(data) < n:
            try:
                packet = (sock.recv(n - len(data))).decode()

            except OSError:
                print("Client -> Connection probably down or terminated (OSError: receiveall()")
                print("Client -> Disconnecting from "+str(sock))
                raise ValueError

            # Something corrupted in transit. Let's just ignore the bad pieces for now.
            except UnicodeDecodeError:
                packet = (sock.recv(n - len(data))).decode('utf-8', 'ignore')
                print(packet)

            if not packet:
                return None

            else:
                data += packet
        return data.encode()

    def receive(self, connection):
        # Read message length and unpack it into an integer
        # Returns None if self.receiveall fails, or nothing at all otherwise.
        sock = connection[0]
        try:
            raw_msglen = self.receiveall(sock, 4)

            if not raw_msglen:
                return None

            msglen = struct.unpack('>I', raw_msglen)[0]
            return self.receiveall(sock, msglen).decode()

        # This socket disconnected. Return 1 so the calling function(probably the listener) knows what happened.
        except ValueError:
            self.disconnect(connection)
            return 1

    def broadcast(self, message):
        for connection in network_tuple:
            self.send(connection, message, signing=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def run_external_command(command):
        # Given a string containing a UNIX command, execute it.
        # Returns 0 -> int (duh)

        os.system(command)
        return 0

    def respond(self, connection, msg):
        # We received a message, reply with an appropriate response.
        # Doesn't return anything.

        global message_list
        global ballet_tuple
        global cluster_rep

        full_message = str(msg)
        sig = msg[:16]
        message = msg[17:]
        address = connection[1]

        # Don't respond to messages we've already responded to.
        if sig in message_list:
            print("Client -> Not responding to "+sig)

        # Do respond to messages we have yet to respond to.
        else:

            # Append signature(hash) to the message list, or in the case of sig=no_prop, do nothing.
            if sig != no_prop:
                message_list.append(sig)

            # Find the address of the socket we're receiving from...
            print('Client -> Received: ' + message + " (" + sig + ")" + "from: " + address)

            # Simple connection test mechanism.
            if message == "echo":
                # Check if Client/Server communication is intact
                print("Client -> echoing...")
                self.send(connection, no_prop+':'+message, signing=False)  # If received, send back

            # Easy way to instruct all nodes to disconnect from each other and exit cleanly.
            if message == "stop":
                self.terminate()

            # If we received a foreign address, connect to it. This is address propagation.
            if message.startswith("ConnectTo:"):
                connect_to_address = message[10:]

                # The address is foreign, connect to it.
                if not self.lookup_socket(connect_to_address):

                    # Don't re-connect to localhost. All kinds of bad things happen if you do.
                    if address == self.get_local_ip() or address == "127.0.0.1":
                        print("Client -> Not connecting to", address + ";", "That's localhost :P")

                    else:
                        local_address = self.get_local_ip()
                        print("Client -> self.get_local_ip() indicates that localhost = "+local_address)
                        new_socket = socket.socket()
                        new_connection = (new_socket, connect_to_address)
                        self.connect(new_connection, connect_to_address, PORT)
                        self.listen(new_connection)

                # The address isn't foreign, don't re-connect to it.
                else:
                    print("Not connecting to", address+";", "We're already connected.")

            if message.startswith('exec:'):
                # Assuming allow_command_execution is set, execute arbitrary UNIX commands in their own threads.
                if allow_command_execution:
                    command = message[5:]
                    print("executing: "+command)

                    # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                    # non-isolated fork of a process.
                    command_process = multiprocessing.Process(target=self.run_external_command,
                                                              args=(command,), name='Cmd_Thread')
                    command_process.start()

                # allow_command_execution is not set, don't execute arbitrary UNIX commands from the network.
                else:
                    print("Not executing command: ", message[5:])

            ''' Very oversimplified method of breaking the symmetry between nodes and choosing one to 'elect' as
            representative for whatever task is at hand. Each node generates a 16-digit random number with a
            Cryptographically Secure Pseudo-Random Number Generator; Whichever node generates the greatest number
            'wins' the election for representative of whatever task it at hand. '''

            if message == "vote":
                ballet_tuple = ([], [])  # Clear the ballet before initiating the vote
                elect_msg = "elect:"

                uid_str = ""  # <-- Will be a random 16-digit number(zeroes included)
                for i in range(0, 16):
                    uid_str += str(random.SystemRandom().randint(0, 9))

                while len(uid_str) != 16:  # Make sure that uid_str is <i>really</i> a 16-digit integer
                    uid_str = uid_str[:-1]

                elect_msg += self.get_local_ip() + ":" + uid_str  # e.x elect:10.1.10.7:9739273648719283

                print("Contributing to the election: "+elect_msg)
                self.broadcast(self.prepare(elect_msg))
                del elect_msg  # we don't need that anymore.

            if message.startswith('elect:'):
                info = message[6:]  # the whole string minus the 'elect:' part
                number = info[-16:]  # e.x 9739273648719283
                address = info[:-17]  # e.x 10.1.10.7

                ballet_tuple[0].append(number)
                ballet_tuple[1].append(address)  # Append number/address to the ballet tuple.

                # We received a vote from every node, and nothing went catastrophically wrong with the network. Cool!
                if len(ballet_tuple[0]) == len(network_tuple) and len(ballet_tuple[0]) != 0:

                    # The numbers we receive from the nodes are stored as strings. We need integers to evaluate their
                    # relative sizes.
                    int_ballet_tuple = [int(i) for i in ballet_tuple[0]]

                    # Be verbose
                    index = int_ballet_tuple.index(max(int_ballet_tuple))
                    print("\n--- " + ballet_tuple[0][index])   # we actually want the string here, not the int.
                    print("--- " + ballet_tuple[1][index] + " won the election for cluster representative\n")

                    # Set this so we can check it later on.
                    cluster_rep = ballet_tuple[1][index]

            # Eventually we'll be able to distribute shared
            # retrievable information, like public keys, across the network.
            if message.startswith("file:"):
                info = message[5:]
                file_hash = info[:16]
                file_length = info[-4:]
                print("\n Client -> Store segment of file: "+file_hash+" of length: "+file_length+"?")

            # Remove the specified node from the network (i.e disconnect from it)
            if message.startswith("remove:"):

                address_to_remove = message[7:]

                try:

                    # Don't disconnect from localhost. That's what self.terminate is for.
                    if address_to_remove != self.get_local_ip() and address_to_remove != "127.0.0.1":

                        print("Client -> Remove -> Disconnecting from " + address_to_remove)

                        # lookup the socket of the address we want to remove
                        sock = self.lookup_socket(address_to_remove)

                        connection_to_remove = (sock, address_to_remove)
                        self.disconnect(connection_to_remove)

                    else:
                        print("Client -> Not disconnecting from localhost, dimwit.")

                except (ValueError, TypeError):
                    # Either the address we're looking for doesn't exist, or we're not connected it it.
                    print("Server -> Sorry, we're not connected to " + address_to_remove)
                    pass

            # End of respond()
            # Propagate the message to the rest of the network.
            print('Client -> broadcasting: '+full_message)
            self.broadcast(full_message)

    def listen(self, connection):
        # Listen for incoming messages and call self.respond() to respond to them.
        # Also, deal with disconnections as they are most likely to throw errors here.
        # Returns nothing.

        def listener_thread(conn):
            in_sock = conn[0]
            global terminated
            listener_terminated = False  # When set, this specific instance of listener_thread is stopped.

            while not listener_terminated or terminated:
                incoming = self.receive(conn)
                msg = incoming
                try:
                    if incoming:
                        self.respond(conn, msg)

                except TypeError:
                    print("Client -> Connection to "+str(in_sock) + "was severed or disconnected." +
                          "(TypeError: listen() -> listener_thread()")

                    self.disconnect(conn)
                    listener_terminated = True

                if incoming == 1:
                    print("Connection to " + str(in_sock) + "doesn't exist, terminating listener_thread()")
                    listener_terminated = True

        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(connection,), name='listener_thread').start()

    def terminate(self):
        # Disconnect from the network and exit the client cleanly.
        # Returns 0 -> int (duh)

        global terminated
        global network_tuple
        print("Client -> Safely terminating our connections...")

        index = 0
        for connection in network_tuple:
            server = connection[0]
            address = connection[1]
            print("Client -> Terminating connection to", address)
            self.disconnect(server, disallow_local_disconnect=False)
            index += 1

        terminated = True
        return 0

    def initialize(self, port=3705, network_architecture="Complete",
                   remote_addresses=None, command_execution=False):
        # Initialize the client, set any global variable that need to be set, etc.

        global allow_command_execution
        global localhost
        global PORT

        PORT = port  # Global variable assignment
        allow_command_execution = command_execution

        # Stage 0
        print("Client -> Initializing...")
        localhost_connection = (localhost, '127.0.0.1')

        try:
            self.connect(localhost_connection, 'localhost', port, local=True)

            print("Client -> Connection to localhost successful")
            print("Client -> Starting listener on localhost...")

            self.listen(localhost_connection)

        except ConnectionRefusedError:

            print("Client -> Connection to localhost was not successful; check that your server is "
                  "up, and try again later.")
            quit(1)

        print("Client -> Attempting to connect to remote server... (Initiating stage 1)")

        # Stage 1
        if network_architecture == "Complete":

            if remote_addresses:

                for remote_address in remote_addresses:
                    sock = socket.socket()

                    try:
                        connection = (sock, remote_address)
                        self.connect(connection, remote_address, port)

                        print("Starting listener on", remote_address)
                        self.listen(connection)

                        self.send(connection, "echo")

                    except ConnectionRefusedError:
                        print("Client -> Unable to connect to remove server; Failed to bootstrap.")
            else:
                print("Client -> Initializing with no remote connections...")
        else:
            print("TODO: Implement other network architectures")  # TODO: implement other architectures
