# Python 3.6.2
import socket
import struct
import inject
import threading
import datetime
from hashlib import sha3_224


# Globals
localhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Nobody likes TIME_WAIT-ing. Add SO_REUSEADDR.

injector = inject.NetworkInjector()

network_tuple = ()  # Global lookup of (sockets, addresses)

message_list = []   # List of message hashes
no_prop = "ffffffffffffffff"  # a message with a true hash indicates that no message propagation is needed.

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

    @staticmethod
    def lookup_socket(address):  # TODO: optimize me
        # Do a brute force search for a specific socket.
        # Maybe this can be optimized by caching the indexes of commonly-used connections?

        for item in network_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

    @staticmethod
    def lookup_address(in_sock):  # TODO: optimize me
        # Do a brute force search for a specific address.
        # Maybe this can be optimized by caching the indexes of commonly-used connections?
        for item in network_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

    ''' The three functions below were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield '''

    def send(self, connection, message, signing=True):
        sock = connection[0]
        address = connection[1]

        if signing:
            msg = self.prepare(message).encode('utf-8')
        else:
            msg = message.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order). Message lengths must be less than (2^32)-4.
        msg = struct.pack('>I', len(msg)) + msg

        try:
            sock.sendall(msg)

        except BrokenPipeError:
            if address != self.get_local_ip() and address != "127.0.0.1":
                print("Server -> Something happened sending to "+address)
                print("Server -> Disconnecting from "+address)
                self.disconnect(connection)

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

    def receive(self, connection):
        in_sock = connection[0]
        # Read message length and unpack it into an integer
        # Returns: (message) -> str

        raw_msglen = self.receiveall(in_sock, 4)

        if not raw_msglen:
            return None

        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.receiveall(in_sock, msglen).decode()

    def broadcast(self, message):
        for connection in network_tuple:
            address = connection[1]
            # Lookup address of client from the network_tuple

            print("Server -> Sending to: "+address)
            self.send(connection, message, signing=False)  # For each of them send the given message( = Broadcast)

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
            print("Server -> Not removing non-existent connection: "+connection)

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def stop(self):
        # Try to gracefully disconnect & disassociate from the network
        print("Client -> stop() -> Trying to gracefully disconnect and disassociate.")

        for connection in network_tuple:
            print("Trying to disconnect from socket: " + str(connection[0]))

            try:
                self.disconnect(connection, disallow_local_disconnect=True)
                print("Successfully disconnected")

            except OSError:
                print("Failed to disconnect from socket: "+str(connection[0]))

        localhost.close()
        print("Server -> Stop() -> Exiting cleanly.")
        quit(0)

    def respond(self, msg, connection):
        # We received a message, reply with an appropriate response.
        # Doesn't return anything.

        global no_prop  # 0xffffffffffffffff
        global message_list

        address = connection[1]

        full_message = str(msg)
        sig = msg[:16]
        message = msg[17:]

        if sig not in message_list:
            print('Server -> Received: ' + message + " (" + sig + ")")  # e.x Server -> Received echo (ffffffffffffffff)

            if message == "echo":
                # If received, two-way communication is functional
                print("Server -> Note: Two-Way communication with", address, "established and/or tested functional")

                self.send(connection, no_prop+":continue", signing=False)

            # We only broadcast messages with hashes we haven't already documented. That way the network doesn't
            # loop indefinitely broadcasting the same message. Also, Don't append no_prop to message_list.
            # That would be bad.
            if sig not in message_list and sig != no_prop:
                message_list.append(sig)

                print("Server -> Broadcasting "+full_message)
                self.broadcast(full_message)

    def disconnect(self, connection, disallow_local_disconnect=True):
        # Try our best to cleanly disconnect from a socket.
        # Doesn't return anything.
        sock = connection[0]
        address = connection[1]
        try:
            if disallow_local_disconnect:
                if address == self.get_local_ip():
                    print("Server -> BUG -> Refusing to disconnect from localhost; that's a terrible idea.")
                    return None
                else:
                    print("\n\n\tSelf.disconnect() called!\t\n\n")
                    print("\nDisconnecting from " + str(sock))
                    print("Disconnecting from ", address)
                    print("Server -> Removing " + str(sock) + " from network_tuple\n")
                    self.remove(connection)
                    local_connection = network_tuple[0]
                    sock.close()
                    message = no_prop+":remove:"+address
                    self.send(local_connection, message, signing=False)
                    self.broadcast(self.prepare("remove:" + address))
                    print("Client -> Successfully disconnected.")

        # Socket not in network_tuple. Probably already disconnected, or the socket was [closed]
        except IndexError:
            print("Already disconnected; passing")
            pass

    def listen(self, connection):
        # Listen for incoming messages in one thread, manage the network injector in another.
        # Doesn't return anything.

        global injector_terminated  # When true, all running network injectors (should) cleanly exit.

        def listener(conn):
            listener_terminated = False  # When set, this thread and this thread only, is stopped.

            while not listener_terminated:
                try:
                    incoming = self.receive(conn)
                    if incoming:
                        self.respond(incoming, conn)

                except (OSError, TypeError):
                    try:
                        print(conn)
                        client = conn[0]
                        address = conn[1]
                        print(address)

                        if address == self.get_local_ip() or address == "127.0.0.1":
                            print("Server -> Something happened with localhost; not disconnecting")
                        else:
                            try:
                                self.disconnect(conn)
                            except ValueError:
                                print("Server -> Socket closed")
                            finally:
                                print("Server -> Connection to "+str(client) + "probably down or terminated;")
                                listener_terminated = True
                    except ValueError:  # socket is [closed]
                        listener_terminated = True

        def start_injector():
            # Start one instance of the network injector and run it until another client connects.
            # Note: The injector itself (i.e inject.py) returns any address that throws a BrokenPipeError on broadcast.
            # This function returns nothing.

            global net_injection
            global injector_terminated

            if not injector_terminated:
                if net_injection:
                    injector_return_value = injector.init(network_tuple)

                    # The mess below handles the collect() loop that would normally be in inject.py

                    current_network_size = len(network_tuple)

                    while 1:
                        network_size = len(network_tuple)
                        if current_network_size != network_size:
                            break  # A new client connected, let's exit the injector.

                        if type(injector_return_value) == str:

                            if injector_return_value != self.get_local_ip() and injector_return_value != "127.0.0.1":

                                print("Server -> Disconnect from faulty connection: " + injector_return_value)

                                # Find the address of the disconnected or otherwise faulty node.
                                sock = self.lookup_socket(injector_return_value)
                                print("\n----")
                                print("\tLooking up socket for "+injector_return_value)
                                print("Found socket: " + str(sock))

                                if sock:
                                    connection_to_disconnect = (sock, injector_return_value)
                                    print("As part of connection: "+str(connection_to_disconnect))
                                    print("Trying to disconnect from: "+str(connection_to_disconnect))
                                    self.disconnect(connection_to_disconnect)
                                    print("----\n")

                            else:
                                print("Server -> Not disconnecting from localhost, dimwit.")

                        # The injector ran cleanly and we still have a multi-node network. Continue as normal.
                        if injector_return_value == 0 and len(network_tuple) >= 1:

                            try:
                                print(network_tuple)
                                injector_return_value = injector.init(network_tuple)  # Eww nested loops.

                            except BrokenPipeError:
                                pass  # We'll get the address of the disconnected device through other methods shortly

                        # Something catastrophically wrong happened and for some reason, there are zero connections
                        # whatsoever. Stop the injector loop immediately so we can deal with the issue at hand.
                        elif len(network_tuple) == 0:
                            break

                        # The size of the network_tuple changed. Either we have remote connections, or a clean
                        # disconnect just occurred. Stop the loop so we can act accordingly.
                        elif len(network_tuple) > 1 or len(network_tuple) != current_network_size:
                            print("!!!")
                            break  # We have remote connections...

                        else:
                            break
            elif injector_terminated:
                print("Terminating Injector...")
                return 0

        # Start listener in a new thread
        print('starting listener thread')
        threading.Thread(target=listener, name='listener_thread', args=(connection,)).start()

        # If applicable, start a new instance of the network injector, killing any other running ones.
        if net_injection:
            injector_terminated = True  # Kill any running network injector(s)
            injector_terminated = False

            threading.Thread(target=start_injector, name='injector_thread', args=()).start()  # Start a new one

    def initialize(self, port=3704, listening=True, method="socket", network_injection=False,
                   network_architecture="complete"):

        if method == "socket":
            global injector
            global localhost
            global net_injection

            address_string = self.get_local_ip()+":"+str(port)  # e.x 10.1.10.3:3705
            net_injection = network_injection  # Didn't want to shadow variable names.

            print("Server -> Initializing...")

            print("Server -> Binding server on: ", address_string, "...", sep='')

            # First, try to bind the server to (this address) port (port). If that doesn't work, exit cleanly.
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

            # Listen for incoming connections.
            while listening:
                try:
                    localhost.listen(5)
                    client, address_tuple = localhost.accept()
                    address = address_tuple[0]

                    self.append(client, address)
                    connection = (client, address)

                    # Our localhost connected, do localhost stuff;
                    if address == self.get_local_ip() or address == "127.0.0.1":
                        print("Server -> localhost has connected.")
                        self.send(connection, "echo")
                        self.listen(connection)
                        print("Server -> Listening on localhost...")

                    # A remote client connected, handle them and send an echo, because why not?
                    else:

                        print("Server -> ", address, " has connected.", sep='')
                        print("Server -> Listening on ", address, sep='')
                        self.listen(connection)
                        self.send(connection, "echo")  # TODO: is this necessary?

                    if network_architecture == "complete":
                        # In a 'complete' network, every node is connected to every other node for redundancy.
                        # Hence, when a new node connects, we broadcast it's address to the  entire network so
                        # every other node can try to connect to it (i.e 'complete' the network).
                        self.broadcast(self.prepare('ConnectTo:' + address))

                except ConnectionResetError:
                    print("Server -> localhost has disconnected")

        else:
            print("TODO: implement other protocols")  # TODO: Implement other protocols
