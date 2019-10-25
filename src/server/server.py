# Python 3.6.2

import os
import sys
import random
import socket
import struct
import datetime
import threading
from hashlib import sha3_224

# Add to PATH
sys.path.insert(0, '../inter/')
sys.path.insert(0, '../inter/modules/')
sys.path.insert(0, '../inter/modules/scripts/')

sys.path.insert(0, '../misc/')

# Imports from PATH
import primitives
import file

# Globals
localhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Nobody likes TIME_WAIT-ing. Add SO_REUSEADDR.

network_tuple = ()  # Global lookup of (sockets, addresses)
message_list = []   # List of message hashes
no_prop = "ffffffffffffffff"  # a message with a true hash indicates that no message propagation is needed.
file_index = 0

net_injection = False
injector_terminated = False
terminated = False
log_level = ""  # "Debug", "Info", or "Warning"; will be set by self.initialize()
sub_node = "Server"
loaded_modules = []

this_dir = os.path.dirname(os.path.abspath(__file__))

try:
    # This works when manually executing init_server.py from the current directory
    os.chdir(this_dir)

except FileNotFoundError:
    # This works when launching with the src/misc/init.py script
    os.chdir("../../server")


sys.path.insert(0, '../inter/modules/')
sys.path.insert(0, '../misc/')

# This will be reset with input values by init()
Primitives = primitives.Primitives(sub_node, log_level)
original_path = os.path.dirname(os.path.realpath(__file__))


class Server:
    
    @staticmethod
    def prepare(message):
        """ Assign unique hashes to messages ready for transport.
            Returns (new hashed message) -> str """

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
    def permute_network_tuple():
        """ Permute the network tuple. Repetitive permutation after each call
            of respond() functionally allows the network to inherit many of the anonymous
            aspects of a mixing network. Packets are sent sequentially in the order of the
            network tuple, which when permuted, thwarts many timing attacks. ''
            Doesn't return """

        cs_prng = random.SystemRandom()
        global network_tuple

        network_list = list(network_tuple)
        cs_prng.shuffle(network_list)
        new_network_tuple = tuple(network_list)
        network_tuple = new_network_tuple

    @staticmethod
    def lookup_socket(address):  # TODO: optimize me
        """Do a brute force search for a specific socket.
           Maybe this can be optimized by caching the indexes of commonly-used connections?"""

        for item in network_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

    @staticmethod
    def lookup_address(in_sock):  # TODO: optimize me
        """Do a brute force search for a specific socket.
           Maybe this can be optimized by caching the indexes of commonly-used connections?"""

        for item in network_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

    """ The two functions below were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield """

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

        except (BrokenPipeError, OSError, AttributeError):
            if address != () and address != "127.0.0.1":

                log_msg = str("Errors occurred sending to " + address + "; Disconnecting...")
                Primitives.log(log_msg, in_log_level="Warning")

                self.disconnect(connection)

    def broadcast(self, message):
        for connection in network_tuple:
            address = connection[1]
            # Lookup address of client from the network_tuple

            log_msg = str("Sending to: "+address)
            Primitives.log(log_msg, in_log_level="Debug")

            self.send(connection, message, signing=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def append(in_socket, address):
        """ Add a connection to the network tuple. Doesn't return."""
        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        connection = (in_socket, address)
        network_list.append(connection)

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def remove(self, connection):
        """Remove a connection from the network tuple. Doesn't return"""
        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        # Identify and remove said connection
        try:
            index = network_list.index(connection)
            network_list.pop(index)

        # Connection not in network tuple, or socket is [closed]
        except ValueError:
            log_msg = str("Not removing non-existent connection: "+str(connection))
            Primitives.log(log_msg, in_log_level="Warning")

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def stop(self):
        """ Attempt to gracefully disconnect and terminate,
        but resort to brute force if needed. """
        global terminated
        global injector_terminated

        localhost_socket = self.lookup_socket("127.0.0.1")
        localhost_connection = (localhost_socket, "127.0.0.1")
        self.send(localhost_connection, "stop")

        log_msg = "Attempting to gracefully disconnect and disassociate from all clients..."
        Primitives.log(log_msg, in_log_level="Info")

        for connection in network_tuple:
            log_msg = str("Trying to disconnect from socket: " + str(connection[0]))
            Primitives.log(log_msg, in_log_level="Debug")

            try:
                self.disconnect(connection, disallow_local_disconnect=True)

            except OSError:
                another_log_msg = str("Failed to disconnect from socket: "+str(connection[0]))
                Primitives.log(another_log_msg, in_log_level="Warning")

            finally:
                Primitives.log("Successfully disconnected", in_log_level="Debug")

        localhost_sock_name = localhost.getsockname()
        localhost.close()

        Primitives.log("Exiting gracefully;", in_log_level="Info")

        terminated = True
        injector_terminated = True

        # Hack the socket.listen() loop in the init() function by connecting to it(localhost),
        # which will force it to terminate.

        temp = socket.socket()
        temp.connect(localhost_sock_name)
        temp.close()

        # noinspection PyProtectedMember
        os._exit(0)

    def respond(self, msg, connection):
        # We received a message, reply with an appropriate response.
        # Doesn't return anything.

        global no_prop  # default: 0xffffffffffffffff
        global message_list

        address = connection[1]
        full_message = str(msg)
        sig = msg[:16]
        message = msg[17:]

        # Server received a unique message. Respond accordingly.
        if sig not in message_list:

            message_received_log_info = str('Server -> Received: ' + message + " (" + sig + ")")
            Primitives.log(message_received_log_info, in_log_level="Info")

            if message == "echo":
                # If received, two-way communication is functional
                echo_received_log = str("Two-Way communication with " + address +
                                        " established and/or tested functional")
                Primitives.log(echo_received_log, in_log_level="Info")

            if message == "stop":
                Primitives.log("Exiting Cleanly", in_log_level="Info")
                self.stop()

            if message.startswith("remove:"):
                address_to_remove = message[7:]

                try:

                    # Don't disconnect from localhost. That's what self.terminate is for.
                    if address_to_remove != Primitives.get_local_ip() and address_to_remove != "127.0.0.1":

                        sock = self.lookup_socket(address_to_remove)

                        if sock:
                            Primitives.log("Remove -> Disconnecting from " + address_to_remove,
                                     in_log_level="Info")

                            # lookup the socket of the address we want to remove
                            connection_to_remove = (sock, address_to_remove)
                            Primitives.log(str("\t--who's connection is: " + str(connection_to_remove)),
                                     in_log_level="Info")
                            self.disconnect(connection_to_remove)

                        else:
                            Primitives.log("Not disconnecting from a non-existent connection",
                                     in_log_level="Warning")

                    else:
                        Primitives.log("Not disconnecting from localhost, dimwit.", in_log_level="Warning")

                except (ValueError, TypeError):
                    # Either the address we're looking for doesn't exist, or we're not connected it it.
                    Primitives.log(str("Sorry, we're not connected to " + address_to_remove),
                             in_log_level="Warning")
                    pass

            if message.startswith("retrieve:"):
                """
                Opposite of write_page() function. This isn't a function because we need access to
                the network to propagate the file contents. Typically sent by a network injector and
                 received from a client, not from a client directly.

                e.x retrieve:(64-bit hash)
                """

                target_page = message[9:]

                address_list = []
                for net_socket, net_address in network_tuple:
                    address_list.append(net_address)

                id_list = []
                for remote_address in address_list:
                    identity = sha3_224(remote_address.encode()).hexdigest()[:16]
                    id_list.append(identity)

                # For every address, sequentially send 'fetch' flags to sync any changes
                # to the page

                fetch_msg = self.prepare("fetch:"+target_page)
                self.broadcast(fetch_msg)

            # We only broadcast messages with hashes we haven't already documented. That way the network doesn't
            # loop indefinitely broadcasting the same message. Also, Don't append no_prop to message_list.
            # That would be bad.

            if sig not in message_list and sig != no_prop:
                message_list.append(sig)

                broadcast_notice = str("Broadcasting "+full_message)
                Primitives.log(broadcast_notice, in_log_level="Info")
                self.broadcast(full_message)

                Primitives.log("Permuting the Network Tuple", in_log_level="Info")
                self.permute_network_tuple()

            if sig == no_prop:
                if message[:5] == "sync:":
                    # This was received with the no_prop flag, however, the Server can't do anything with sync: calls.
                    # Send this to localhost Client.

                    Primitives.log("Violating the no_prop policy for localhost", in_log_level="Warning")

                    localhost_address = "127.0.0.1"
                    localhost_socket = self.lookup_socket(localhost_address)
                    localhost_connection = (localhost_socket, localhost_address)

                    self.send(localhost_connection, full_message, signing=False)

    def disconnect(self, connection, disallow_local_disconnect=True):
        """Try to disconnect from a socket as cleanly as possible.
           Doesn't return anything. """

        sock = connection[0]
        address = connection[1]
        try:
            if disallow_local_disconnect:
                Primitives.log("Terminated:"+str(terminated), in_log_level="Debug")

                if address == Primitives.get_local_ip() and not terminated:

                    Primitives.log("(Bug) Refusing to disconnect from localhost;"
                             " that's a terrible idea...", in_log_level="Warning")
                    return None

                else:

                    Primitives.log("\n\tSelf.disconnect() called.\n", in_log_level="Info")

                    verbose_connection_msg = str("Disconnecting from " + address
                                                 + "\n\t(  " + str(sock) + "  )")

                    Primitives.log(verbose_connection_msg, in_log_level="Info")

                    conn_remove_msg = str("Server -> Removing " + str(sock) + " from network_tuple")
                    Primitives.log(conn_remove_msg, in_log_level="Info")
                    self.remove(connection)
                    sock.close()

                    Primitives.log("Successfully Disconnected.", in_log_level="Info")

        # Socket not in network_tuple. Probably already disconnected, or the socket was [closed]
        except IndexError:
            Primitives.log("Already disconnected from that address; passing;", in_log_level="Warning")

    def listen(self, connection):
        """Listen for incoming messages in one thread, manage the network injector in another.
        Doesn't return anything. """

        global injector_terminated  # If True: cleanly exit all network injectors.

        def listener(conn):
            listener_terminated = False  # When set, this thread and this thread only, is stopped.

            while not listener_terminated and not terminated:
                try:
                    incoming = Primitives.receive(conn)

                    # Primitives.receive() returns none if something goes wrong.
                    if incoming:
                        self.respond(incoming, conn)

                except (OverflowError, TabError):  # OSError, TypeError
                    # OSError - Something terrible happened trying to receive from a node
                    # TypeError - A socket is apparently NoneType now. That's bad

                    try:
                        client = conn[0]
                        address = conn[1]

                        print("TERMINATED: "+str(terminated))
                        if address == Primitives.get_local_ip() or address == "127.0.0.1" and not terminated:
                                Primitives.log("Something happened to localhost; not disconnecting",
                                         in_log_level="Warning")
                                print("TERMINATED: "+str(terminated))
                        else:
                            try:
                                self.disconnect(conn)
                            except ValueError:
                                Primitives.log("Socket Closed", in_log_level="Warning")
                            finally:
                                connection_down_msg = str("Server -> Connection to " + str(client)
                                                          + "probably down or terminated;")

                                Primitives.log(connection_down_msg, in_log_level="Warning")

                                # Don't leave zombie listeners running
                                listener_terminated = True
                                
                            if terminated:
                                os._exit(0)
                                
                    except OSError:
                        pass

                except ValueError:  # socket is [closed]
                    listener_terminated = True

        def start_injector():
            # Start one instance of the network injector and run it until another client connects.
            # Note: The injector itself (i.e inject.py) returns any address that throws a BrokenPipeError on broadcast.
            # This function returns nothing.

            os.chdir(original_path)

            import inject
            injector = inject.NetworkInjector()

            global net_injection
            global injector_terminated
            global loaded_modules

            if not injector_terminated or terminated:
                if net_injection:
                    injector_return_value = injector.init(network_tuple, loaded_modules)

                    # The mess below handles the collect() loop that used to be in inject.py

                    current_network_size = len(network_tuple)

                    while not terminated or not injector_terminated:
                        network_size = len(network_tuple)  # Keep this up to date

                        if terminated:
                            injector_terminated = True
                            break

                        if current_network_size != network_size:
                            break  # A new client connected, let's exit the injector.

                        if type(injector_return_value) == str:
                            """ Something went wrong sending to a given address. The injector
                            doesn't have proper error handling because it's a disposable thread
                            and a waste of lines, so we'll handle it here """

                            message_send_successful = (injector_return_value == Primitives.get_local_ip())
                            if message_send_successful and injector_return_value != "127.0.0.1":

                                faulty_conn_disconnect_msg = str("Server -> Attempting to "
                                                                 "disconnect from faulty"
                                                                 " connection: "
                                                                 + injector_return_value)

                                Primitives.log(faulty_conn_disconnect_msg, in_log_level="Warning")

                                # Find the address of the disconnected or otherwise faulty node.
                                sock = self.lookup_socket(injector_return_value)

                                Primitives.log(str("\tLooking up socket for "+injector_return_value),
                                         in_log_level="Warning")

                                Primitives.log(str("\tFound socket: " + str(sock)), in_log_level="Info")

                                if sock:
                                    # Be really verbose.

                                    connection_to_disconnect = (sock, injector_return_value)

                                    found_connection_msg = str("\tAs part of connection: " +
                                                               str(connection_to_disconnect))
                                    Primitives.log(found_connection_msg, in_log_level="Info")

                                    disconnect_attempt_msg = str("Trying to disconnect from: " +
                                                                 str(connection_to_disconnect))

                                    Primitives.log(disconnect_attempt_msg, in_log_level="Info")

                                    self.disconnect(connection_to_disconnect)

                            else:
                                Primitives.log("Not disconnecting from localhost, dimwit.", in_log_level="Warning")

                        # The injector ran cleanly and we still have a multi-node network. Continue as normal.
                        if injector_return_value == 0 and len(network_tuple) >= 1:

                            try:
                                Primitives.log(str(network_tuple), in_log_level="Debug")
                                Primitives.log("Permuting the network tuple... ", in_log_level="Info")
                                Primitives.log(str(network_tuple), in_log_level="Debug")

                                # Eww nested loops.
                                injector_return_value = injector.init(network_tuple, loaded_modules)

                            except BrokenPipeError:
                                pass  # We'll get the address of the disconnected device through other methods shortly

                        # Something catastrophically wrong happened and for some reason, there are zero connections
                        # whatsoever. Stop the injector loop immediately so we can deal with the issue at hand.

                        elif len(network_tuple) == 0:
                            break

                        # The size of the network_tuple changed. Either we have remote connections, or a clean
                        # disconnect just occurred. Stop the loop so we can act accordingly.
                        elif len(network_tuple) > 1 or len(network_tuple) != current_network_size:
                            Primitives.log("Remote connections detected, stopping the network injector...",
                                     in_log_level="Info")
                            break  # We have remote connections...

                        else:
                            break
            elif injector_terminated:
                Primitives.log("Terminating the Network Injector", in_log_level="Info")
                return

        # Start listener in a new thread
        Primitives.log("Starting a new listener thread", in_log_level="Info")
        threading.Thread(target=listener, name='listener_thread', args=(connection,)).start()

        # If applicable, start a new instance of the network injector, killing any other running ones.
        if net_injection and not terminated:
            injector_terminated = True  # Kill any running network injector(s)
            injector_terminated = False

            threading.Thread(target=start_injector, name='injector_thread', args=()).start()

    def initialize(self, port=3704, listening=True, method="socket", network_injection=False,
                   network_architecture="complete", default_log_level='Warning', modules=None):

        if method == "socket":
            global localhost
            global net_injection
            global terminated
            global log_level
            global loaded_modules
            global sub_node
            global Primitives

            log_level = default_log_level
            Primitives = primitives.Primitives(sub_node, log_level)

            for item in modules:
                import_str = "import " + item
                loaded_modules.append(item)
                exec(import_str)

            # Set parameters and global variables from their default values

            address_string = Primitives.get_local_ip()+":"+str(port)  # e.x 10.1.10.3:3705
            net_injection = network_injection  # Didn't want to shadow variable names.

            Primitives.log("Initializing... ", in_log_level="Info")

            Primitives.log(str("Server -> Binding server on: " + address_string + "..."),
                     in_log_level="Info")

            # First, try to bind the server to (this address) port (port). If that doesn't work, exit cleanly.

            try:
                localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                localhost.bind(('', port))
                Primitives.log(str("Successfully bound server on port: " + str(port)), in_log_level="Info")

            except OSError:
                Primitives.log(str("Failed to bind server on " + address_string +
                                   "; Please try again later."), in_log_level="Info")
                self.stop()

            if listening:
                Primitives.log("Server -> Now Listening for incoming connections...", in_log_level="Info")

            # Listen for incoming connections.
            while listening:
                try:

                    localhost.listen(5)
                    client, address_tuple = localhost.accept()

                    if not terminated:
                        address = address_tuple[0]
                        self.append(client, address)
                        connection = (client, address)

                        # Our localhost connected, do localhost stuff;
                        if address == Primitives.get_local_ip() or address == "127.0.0.1":

                            Primitives.log("Localhost has connected.", in_log_level="Info")

                            self.send(connection, str(no_prop+':'+"echo"), signing=False)
                            self.listen(connection)
                            Primitives.log("Listening on localhost...", in_log_level="Info")

                            # Make the client connect back to localhost if network_architecture=mesh
                            localhost_socket = self.lookup_socket("127.0.0.1")
                            localhost_connection = (localhost_socket, "127.0.0.1")
                            self.send(localhost_connection, no_prop + ":ConnectTo:" + address, signing=False)

                        # A remote client connected, handle them and send an echo, because why not?
                        else:
                            Primitives.log(str(address + " has connected."), in_log_level="Info")

                            Primitives.log(str("Listening on: "+address), in_log_level="Info")
                            self.listen(connection)

                            if network_architecture == "complete":
                                self.send(connection, no_prop+":echo", signing=False)  # WIP

                        if network_architecture == "complete":
                            # In a 'complete' network, every node is connected to every other node for redundancy.
                            # Hence, when a new node connects, we broadcast it's address to the  entire network so
                            # every other node can try to connect to it (i.e 'complete' the network).
                            self.broadcast(no_prop + ':ConnectTo:' + address)

                        elif network_architecture == "mesh":
                            # In mesh configuration, tell localhost client to connect back to the server
                            # of any remote client which connects to localhost server.

                            localhost_socket = self.lookup_socket("127.0.0.1")
                            localhost_connection = (localhost_socket, "127.0.0.1")
                            self.send(localhost_connection, no_prop + ":ConnectTo:" + address, signing=False)


                    elif terminated:
                        sys.exit(0)

                except (ConnectionResetError):
                    Primitives.log("Server -> localhost has disconnected", in_log_level="Warning")

                # OSError will occur on Windows Systems we try to terminate. Handle that.
                except OSError:
                    sys.exit(0)
