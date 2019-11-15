# Python 3.6.2
import socket
import struct
import threading
import datetime
import os
import random
import sys
import secrets
from time import sleep
from hashlib import sha3_224

# Switch to the directory containing client.py
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)

# Insert the server, misc, and src/inter directories to PATH so we can use modules like inject, vote, discover, etc.
sys.path.insert(0, (os.path.abspath('../server')))
sys.path.insert(0, (os.path.abspath('../misc')))
sys.path.insert(0, (os.path.abspath('../inter/')))
sys.path.insert(0, (os.path.abspath('../inter/modules')))

# Imports from PATH
import primitives

# Globals
localhost = socket.socket()
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Nobody likes TIME_WAIT-ing. Add SO_REUSEADDR.

# Mutable state; Write with writeState(), Read with readState(). Contains default values until changed
nodeState = [(), [], False, False, [], "", [], 0, [], [], False, False, False]


# Immutable state: Constant node parameters set upon initialization
PORT = 3705
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]
log_level = ""  # "Debug", "Info", or "Warning"; To be set by init
sub_node = "Client"
no_prop = "ffffffffffffffff"  # True:[message] = No message propagation.
ring_prop = "eeeeeeeeeeeeeeee"
SALT = None  # Will be set to a 128-bit hexadecimal token(by self.init) for making address identifiers
ADDR_ID = None  # Another 128-bit hexadecimal token that wil be salted with SALT, and set by init()
original_path = os.path.dirname(os.path.realpath(__file__))
network_size = 0
network_architecture = ""  # "complete" or "mesh"
output_node = ""  # Address of one remote node from init_client

os.chdir(original_path)
Primitives = primitives.Primitives(sub_node, log_level)


class Client:

    @staticmethod
    def overwrite_nodestate(in_nodestate):
        global nodeState
        nodeState = in_nodestate

    @staticmethod
    def write_nodestate(in_nodestate, index, value, void=True):
        global nodeState

        in_nodestate[index] = value

        nodeState = list(in_nodestate)

        if not void:
            return nodeState

    def read_nodestate(self, index):
        return nodeState[index]

    @staticmethod
    def prepare(message):
        """ Assign unique hashes to messages ready for transport.
            Returns (new hashed message) -> str """

        out = ""

        # Assign a timestamp
        timestamp = str(datetime.datetime.utcnow())
        stamped_message = timestamp + message
        out += stamped_message

        # Generate the hash and append the message to it
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = sig + ":" + message
        return out

    def lookup_socket(self, address, ext_net_tuple=None):  # TODO: optimize me
        """Brute force search the network tuple for a socket associated with a given address.
            Return socket object if found.
            Returns 0(-> int) if not found
        """
        if ext_net_tuple:
            net_tuple = ext_net_tuple

        else:
            net_tuple = self.read_nodestate(0)

        for item in net_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

        return 0  # Socket not found

    def lookup_address(self, in_sock, ext_net_tuple=None):  # TODO: optimize me
        """Brute force search the network tuple for an address associated with a given socket.
            Return a string containing an address if found.
            Returns 0 (-> int) if not found
        """
        if ext_net_tuple:
            net_tuple = ext_net_tuple
        else:
            net_tuple = self.read_nodestate(0)

        for item in net_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

        return 0  # Address not found

    def permute_network_tuple(self):
        """ Permute the network tuple. Repetitive permutation after each call
            of respond() functionally allows the network to inherit many of the anonymous
            aspects of a mixing network. Packets are sent sequentially in the order of the
            network tuple, which when permuted, thwarts many timing attacks. ''
            Doesn't return """

        Primitives.log("Permuting the network tuple", in_log_level="Info")

        net_tuple = self.read_nodestate(0)
        net_list = list(net_tuple)

        cs_prng = random.SystemRandom()
        cs_prng.shuffle(net_list)

        # Tuples are immutable. We have to overwrite the exiting one to 'update' it.
        net_new_tuple = tuple(net_list)
        self.write_nodestate(nodeState, 0, net_new_tuple)

    def append(self, in_socket, address):
        """ Append a given connection object(tuple of (socket, address)) to the network tuple.
            Doesn't return """

        net_tuple = self.read_nodestate(0)
        # Tuples are immutable; convert it to a list.
        net_list = list(net_tuple)

        connection = (in_socket, address)
        net_list.append(connection)

        net_tuple = tuple(net_list)
        self.write_nodestate(nodeState, 0, net_tuple)

        Primitives.log("Successfully appended connection to Network tuple." +
                       "\nConnection:" + str(connection) +
                       "\nNew Network Tuple: " + str(net_tuple), in_log_level="Debug")

    def remove(self, connection):
        """ Remove a given connection object(tuple of (socket, address)) from the network tuple.
            Doesn't return """

        # Tuples are immutable; convert it to a list.
        net_tuple = self.read_nodestate(0)

        net_list = list(net_tuple)

        # Identify and remove said connection
        try:
            index = net_list.index(connection)
            net_list.pop(index)

        # Connection not in network tuple, or socket is [closed]
        except ValueError:
            Primitives.log(str("Not removing non-existent connection: " + str(connection)), in_log_level="Warning")
            return None

        # (Again) tuples are immutable; replace the old one with the new one
        net_tuple = tuple(net_list)

        self.write_nodestate(nodeState, 0, net_tuple)

        Primitives.log("Successfully removed connection from Network tuple." +
                       "\nConnection:" + str(connection) +
                       "\nNew Network Tuple: " + str(net_tuple), in_log_level="Debug")

    def connect(self, connection, address, port, local=False):
        """ Connect to a remote server and handle the connection(i.e append it).
            Doesn't return. """

        connecting_to_server = self.read_nodestate(2)
        sock = connection[0]

        # Make a real copy of the network tuple
        # Then append our new connection (will be removed if connection fails)
        net_tuple = tuple(self.read_nodestate(0))

        # Don't connect to an address we're already connected to.
        if connection in net_tuple or self.lookup_socket(address) != 0:

            not_connecting_msg = str("Not connecting to " + connection[1] + " (We're already connected.)")

            Primitives.log(not_connecting_msg, in_log_level="Warning")
            self.remove((sock, address))

        # Do connect to nodes we are not already connected to
        else:
            # Also don't try to connect to multiple servers at once in the same thread.
            if not connecting_to_server:
                # connecting_to_server is a mutex which prevents this function
                # from making external connections when it's not supposed to.

                self.write_nodestate(nodeState, 2, True)  # set connecting_to_server = True

                if not local:

                    Primitives.log(str("Connecting to " + address), in_log_level="Info")
                    sock.connect((address, port))
                    Primitives.log("Successfully connected.", in_log_level="Info")
                    self.append(sock, address)
                    self.write_nodestate(nodeState, 2, False)  # set connecting_to_server = False

                elif local:
                    self.remove((sock, address))

                    Primitives.log("Connecting to localhost server...", in_log_level="Info")

                    sock.connect(("127.0.0.1", port))
                    # The socket object we apppended earlier was automatically
                    # destroyed by the OS because connections to 0.0.0.0 are illegal...
                    # Connect to localhost with raddr=127.0.0.1...

                    Primitives.log("Successfully connected to localhost server", in_log_level="Info")
                    self.write_nodestate(nodeState, 2, False)  # set connecting_to_server = False

    def disconnect(self, connection, disallow_local_disconnect=True):
        """ Try to disconnect from a remote server and remove it from the network tuple.
          Returns None if you do something stupid. otherwise don't return """

        # 1. Input validation
        try:
            sock = connection[0]
            address_to_disconnect = connection[1]

        except TypeError:
            Primitives.log("Expected a connection tuple, got:", in_log_level="Warning")
            Primitives.log(str('\t') + str(connection), in_log_level="Warning")
            return None

        # 2. Try to disconnect from said node.
        try:

            # Don't disconnect from localhost unless told to. That's done with self.terminate().
            if disallow_local_disconnect:
                if address_to_disconnect == Primitives.get_local_ip() or address_to_disconnect == "127.0.0.1":
                    Primitives.log("Not disconnecting from localhost dimwit.", in_log_level="Warning")

                # Do disconnect from remote nodes. That sometimes makes sense.
                else:
                    verbose_connection_msg = str("Disconnecting from " + address_to_disconnect
                                                 + "\n\t(  " + str(sock) + "  )")
                    Primitives.log(verbose_connection_msg, in_log_level="Info")

                    self.remove(connection)

                    try:
                        sock.close()

                    except (OSError, AttributeError):
                        close_fail_msg = str("Failed to close the socket of "
                                             + address_to_disconnect
                                             + " -> OSError -> disconnect()")
                        Primitives.log(close_fail_msg, in_log_level="Warning")

                    finally:
                        Primitives.log("Successfully disconnected.", in_log_level="Info")

        # Either the socket in question doesn't exist, or the socket is probably [closed].
        except (IndexError, ValueError):
            Primitives.log("Already disconnected from that address, passing...", in_log_level="Warning")
            pass

    """ The following function was written by StackOverflow user 
    Adam Rosenfield, then modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield """

    def send(self, connection, message, sign=True):
        """Helper function to encode a given message and send it to a given server.
            Set sign=False to disable automatic message signing(useful for no_prop things)
            Doesn't Return. """

        sock = connection[0]

        if sign:
            msg = self.prepare(message).encode('utf-8')
        else:
            msg = message.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg

        # Attempt to send the message through normal means.
        try:
            sock.sendall(msg)

        # Socket probably disconnected, let's do the same and remove it
        # from the network tuple to avoid conflict.
        except OSError:
            self.disconnect(connection)

    def broadcast(self, message, do_mesh_propagation=True):
        global ring_prop
        # do_message_propagation=None means use global config in nodeState[12]

        self.permute_network_tuple()
        net_tuple = self.read_nodestate(0)

        # If not bootstrapped, do ring network propagation. Else, do fully-complete style propagation.
        message_list = self.read_nodestate(1)

        if do_mesh_propagation == "not set":
            do_mesh_propagation = self.read_nodestate(12)

        if not do_mesh_propagation:
            Primitives.log("Message propagation mode: ring", in_log_level="Debug")
            # Network not bootstrapped yet, do ring network propagation
            if message[:16] != ring_prop:
                message = ring_prop + ":" + message
                self.write_nodestate(nodeState, 1, message_list)

        if do_mesh_propagation:
            """ network bootstrapped or do_mesh_propagation override is active, do fully-complete/mesh style
                message propagation """
            Primitives.log("Message propagation mode: fully-complete/mesh", in_log_level="Debug")

        for connection in net_tuple:
            self.send(connection, message, sign=False)  # Send a message to each node( = Broadcast)

    @staticmethod
    def run_external_command(command):
        # Given a string containing a UNIX command, execute it.
        # Disable this by setting command_execution=False
        # Returns 0 -> (int)

        os.system(command)
        return 0

    @staticmethod
    def write_to_page(page_id, data, signing=True):
        global ADDR_ID
        """ Append data to a given pagefile by ID."""

        Primitives.log("Writing to page:" + page_id, in_log_level="Info")
        os.chdir(original_path)

        # Write page data pseudonymously with ADDR_ID
        if signing:

            """ADDR_ID is a cryptographic hash of this node''s externally reachable IP address, salted with a unique
               random token generated upon initialization. ADDR_ID is used as an anonymous, common identifier
               which external nodes can use to direct messages to anonymous destination nodes without requiring them
               to reveal their identity."""

            data_line = str(ADDR_ID + ":" + data + "\n")

        # Write data completely anonymously
        else:

            data_line = str(data + "\n")

        file_path = ("../inter/mem/" + page_id + ".bin")
        print('Writing '+data + " to " + page_id + ".bin")

        this_page = open(file_path, "a+")
        this_page.write(data_line)
        this_page.close()

    def respond(self, connection, msg):
        """ We received a message, reply with an appropriate response.
            Doesn't return. """

        global network_architecture
        global network_size
        global log_level
        global nodeState
        global ring_prop

        full_message = str(msg)
        message = full_message[17:]  # Message without signature
        sig = full_message[:16]  # Just the signature
        address = connection[1]

        os.chdir(original_path)

        net_tuple = self.read_nodestate(0)

        message_list = self.read_nodestate(1)

        propagation_allowed = True

        if address == "127.0.0.1":
            Primitives.log("Received message from 127.0.0.1; This is a violation of protocol; "
                           "replacing address with Local IP.", in_log_level="Debug")
            # Replying to localhost is strictly disallowed. Replace localhost with actual local IP.
            address = Primitives.get_local_ip()

        # Introduce additional network mixing anonymity by introducing a random delay makes it difficult or
        # impossible to derive message paths through timing analysis alone.

        sleep(random.uniform(0.008, 0.05))  # 8mS - 50mS

        if sig == ring_prop:

            message = full_message[17:]  # Remove the ring-propagation deliminator
            message_sig = message[:16]  # Signature after removing ring_prop

            sig = message_sig
            message = message[17:]  # remove the signature

            new_message_list = list(message_list)
            new_message_list.append(message_sig)
            self.write_nodestate(nodeState, 1, new_message_list)

        # Don't respond to messages we've already responded to.
        if sig in message_list:

            not_responding_to_msg = str("Not responding to " + sig)
            Primitives.log(not_responding_to_msg, in_log_level="Debug")

        # Do respond to messages we have yet to respond to.
        elif sig not in message_list or sig == no_prop:

            if len(message) < 100 and "\n" not in message:
                message_received_log = str('Received: ' + message
                                           + " (" + sig + ")" + " from: " + address)

                # e.x "Client -> Received: echo (ffffffffffffffff) from: 127.0.0.1"

            else:
                message_received_log = str('Received: ' + message[:16] + "(message truncated)"
                                           + " (" + sig + ")" + " from: " + address)

            Primitives.log(message_received_log, in_log_level="Info")

            # If received, send back to confirm the presence of successful two-way communication
            if message == "echo":
                import echo

                """ Simple way to test our connection to a given node."""

                Primitives.log("echoing...", in_log_level="Info")
                echo.initiate(self.read_nodestate(0), network_architecture, connection, no_prop)

            # Terminate this node and quit
            if message == "stop":
                """ instruct all nodes to disconnect from each other and exit cleanly."""

                # Enable fully-complete/mesh propagation, regardless of actual network architecture,
                # to ensure that all nodes actually die on command

                # Inform localhost to follow suit.
                localhost_connection = (localhost, "127.0.0.1")
                self.send(localhost_connection, "stop")  # TODO: should we use no_prop here?

                # The node will already be terminated by the time it gets to the end of the function and runs the
                # message propagation algorithm; broadcast now, then stop
                self.broadcast(full_message, do_mesh_propagation=True)
                propagation_allowed = False

                # Do so ourselves
                self.terminate()

            # Set various network topology attributes on-the-fly
            if message.startswith('config:'):

                arguments = Primitives.parse_cmd(message)  # arguments[0] = variable to configure; [1] = value
                print(str(arguments))

                if arguments[0] == "network_size":

                    try:
                        new_network_size = int(arguments[1])
                        network_size = new_network_size
                        Primitives.log("Successfully set network_size to: " + str(network_size), in_log_level="Info")

                    except TypeError:

                        Primitives.log("config: target value not int; ignoring...", in_log_level="Warning")

                elif arguments[0] == "network_architecture":
                    # Changes from any architecture --> mesh must be done while network size <= 2
                    # any architecture --> fully-connected should always work

                    new_network_architecture = arguments[1]

                    if type(new_network_architecture) == str:
                        network_architecture = new_network_architecture
                        Primitives.log("Successfully set network_architecture to: " + network_architecture,
                                       in_log_level="Info")

            # Instruct clients to connect to remote servers.
            if message.startswith("ConnectTo:"):

                """ConnectTo: Instructs external clients to connect to remote servers.
                In fully-connected mode,  ConnectTo: is sent by each node being connected to when a new node 
                joins the network, with one ConnectTo: flag per node in their network table], instructing the new node 
                to connect to  [each node in their network table]. As long as all nodes respond to ConnectTo: flags,
                (if network_architecture = "complete" in init_client/init_server) the 
                network will always be fully-connected.

                Elsewhere in the documentation and code, this bootstrapping mechanism is
                referred to as "address propagation"
                """

                # remove the 'ConnectTo:' flag from the message, leaving only the external address to connect to.
                connect_to_address = message[10:]

                # lookup_socket will return 0 if we're not already connected to said address (above)
                connection_status = self.lookup_socket(connect_to_address)

                Primitives.log(str(net_tuple), in_log_level="Debug")

                # If we're not already connected and making this connection won't break anything, connect now.
                if connection_status == 0:

                    remote_adress_is_localhost = connect_to_address == Primitives.get_local_ip() or \
                                                 connect_to_address == "127.0.0.1"

                    # Don't connect to localhost multiple times;
                    # All kinds of bad things happen if you do.
                    if remote_adress_is_localhost:

                        not_connecting_msg = str("Not connecting to " + connect_to_address + "; That's localhost :P")
                        Primitives.log(not_connecting_msg, in_log_level="Warning")

                    else:

                        mesh_network = (network_architecture == "mesh")  # True if network architecture is mesh
                        sent_by_localhost = (address == "127.0.0.1" or address == Primitives.get_local_ip())

                        print('\n\n')
                        print("\tNetwork Architecture: " + network_architecture)
                        print("\tNetwork Architecture is mesh: " + str(mesh_network))
                        print("\tRemote Address is Localhost: " + str(remote_adress_is_localhost))
                        print("\tReceived packet from Localhost: " + str(sent_by_localhost))
                        print("\n\n")

                        """ In a fully-connected network, act on all ConnectTo: packets;
                            In a mesh network, only act on ConnectTo: packets originating from localhost
                            (ConnectTo: is never sent with message propagation -- ConnectTo: packets received from
                             localhost always really originate from localhost) """

                        if (mesh_network and sent_by_localhost) or not mesh_network:

                            local_address = Primitives.get_local_ip()

                            # Be verbose
                            Primitives.log(str("self.lookup_socket() indicates that we're not"
                                               " connected to " + connect_to_address), in_log_level="Info")

                            Primitives.log(str("Primitives.get_local_ip() indicates that"
                                               " localhost = " + local_address), in_log_level="Info")

                            new_socket = socket.socket()

                            new_connection = (new_socket, connect_to_address)

                            # If we're not connected to said node
                            if not connection_status:
                                try:
                                    self.connect(new_connection, connect_to_address, PORT)
                                    self.listen(new_connection)

                                except OSError:
                                    """ Most Likely a Bad Fie Descriptor in self.connect().
                                    I don't know what to do about that, so we'll just warn the user."""

                                    Primitives.log(str("Unable to connect to: " + str(connect_to_address)),
                                                   in_log_level="Warning")

                # Don't connect to an address we're already connected to...
                elif connection_status != 0:
                    already_connected_msg = str("Not connecting to " +
                                                connect_to_address +
                                                ";" +
                                                "We're already connected.")
                    Primitives.log(already_connected_msg, "Warning")

            # If allowed by client configuration, execute a shell command in the operating system's default terminal
            if message.startswith('exec:'):
                import exec

                exec.initiate(message, allow_command_execution)

            # Create a new pagefile in src/inter/mem which will presumably store some data generated by a
            # concurrent network algorithm
            if message.startswith("newpage:"):
                """ Create a new pagefile that we'll presumably do some 
                parallel or distributed operations with.
                e.x newpage:(64-bit identifier provided by sender)"""

                page_id = message[8:]
                new_filename = str("../inter/mem/" + page_id + ".bin")
                Primitives.log("Creating new page with id: " + str(page_id), in_log_level="Info")

                os.chdir(original_path)
                newpage = open(new_filename, "a+")

                page_list = self.read_nodestate(6)
                page_list.append(newpage)

                self.write_nodestate(nodeState, 6, page_list)

            # Retrieve a file from distributed memory by instructing all nodes to sync the contents of some pagefile
            if message.startswith("fetch:"):
                # fetch:pagefile:[optional task identifier]
                """ Broadcast the contents of [page id] to maintain distributed memory """

                arguments = Primitives.parse_cmd(message)

                page_id = arguments[0]

                # Read contents of page
                os.chdir(original_path)
                pagefile = open("../inter/mem/" + page_id + ".bin", "r+")

                page_lines = pagefile.readlines()

                # Don't sync comments
                for string in page_lines:
                    if string[:1] == "#":
                        page_lines.remove(string)

                page_contents = ''.join(page_lines)

                if arguments[1] == "discovery":
                    is_cluster_rep = self.read_nodestate(11)

                    if is_cluster_rep or len(page_lines) == network_size:
                        sync_msg = self.prepare("sync:" + page_id + ":" + page_contents)
                        self.broadcast(sync_msg, do_mesh_propagation=True)

                else:
                    sync_msg = self.prepare("sync:" + page_id + ":" + page_contents)
                    self.broadcast(sync_msg, do_mesh_propagation=True)

            # Write received pagefile data to disk
            if message.startswith("sync:"):
                """ Update our pagefile with data from another node (such as another node's completed work)
                Translation: write arbitrary data to page [page id] 
                Syntax: sync:(page id):(data)
                """

                os.chdir(original_path)
                page_id = message[5:][:16]  # First 16 bytes after removing the 'sync:' flag
                sync_data = message[22:]

                Primitives.log("Syncing " + sync_data + " into page:" + page_id, in_log_level="Debug")

                file_path = "../inter/mem/" + page_id + ".bin"

                file_exists = False

                try:
                    existing_pagelines = open(file_path, "r+").readlines()
                    file_exists = True

                except FileNotFoundError:
                    Primitives.log("Cannot open a non-existent page")
                    existing_pagelines = []  # Stop PyCharm from telling me this is referenced before assignment

                if file_exists:
                    duplicate = False
                    local = False

                    Primitives.log("Receiving " + str(len(sync_data)) + " bytes of data from network",
                                   in_log_level="Info")

                    for line in existing_pagelines:

                        if log_level == "Debug":
                            print("Line: "+line)
                            print('Data: '+sync_data)

                        if line == sync_data:
                            duplicate = True
                            Primitives.log("Not writing duplicate data into page " + page_id)
                            break

                    if not duplicate:
                        data_id = sync_data[:16]
                        local_id = sha3_224(Primitives.get_local_ip().encode()).hexdigest()[:16]

                        if data_id == local_id:
                            # Don't re-write data from ourselves. We already did that with 'corecount'.
                            print("Not being hypocritical in page " + page_id)
                            local = True

                        if not local:
                            if sync_data == "" or sync_data == " " or sync_data == "\n":
                                pass

                            else:
                                if log_level == "Debug":
                                    print("Writing " + sync_data + "to page " + page_id)
                                    self.write_to_page(page_id, sync_data, signing=False)
                                else:
                                    Primitives.log("Writing " + str(len(sync_data)) + " bytes to " + page_id + ".bin",
                                                   in_log_level="Info")

                    # https://stackoverflow.com/a/1216544
                    # https://stackoverflow.com/users/146442/marcell
                    # The following two lines of code are the work were written by "Marcel" from StackOverflow.

                    # Remove duplicate lines from page
                    unique_lines = set(open(file_path).readlines())
                    open(file_path, 'w').writelines(set(unique_lines))

                    # Remove any extra newlines from page
                    raw_lines = list(set(open(file_path).readlines()))

                    existing_lines = [raw_line for raw_line in raw_lines
                                if raw_line != "\n" and raw_line[:2] != "##"]

                    # Write changes to page
                    open(file_path, 'w').writelines(set(existing_lines))

                    # Wait for each node to contribute before doing module-specific I/O
                    Primitives.log("\n\t" + str(len(existing_lines)) + " Node(s) have contributed to the network."
                                                                 "\n The network tuple(+1) is of length: "
                                   + str(len(net_tuple) + 1), in_log_level="Debug")

                    if len(existing_lines) >= network_size:
                        pass
                        # We've received contributions from every node on the network.
                        # Now do module-specific I/O

                    else:
                        print()

                        module_loaded = self.read_nodestate(5)
                        election_list = self.read_nodestate(9)
                        is_cluster_rep = self.read_nodestate(11)

                        if module_loaded == "discover":
                            # TODO: Make this support multiple peer discoveries without reinitializing

                            hosts_pagefile = ''.join(
                                [item[0][10:] for item in election_list if item[0][:10] == "discovery-"])

                            added_peers = open("../inter/mem/" + hosts_pagefile + ".bin", "r+").readlines()

                            if is_cluster_rep:
                                self.broadcast(self.prepare("fetch:" + hosts_pagefile + ":discovery"),
                                               do_mesh_propagation=False)

                            module_loaded = ""
                            self.write_nodestate(nodeState, 5, module_loaded)

            if message.startswith("find:"):
                import finder
                finder.respond_start(message, sub_node, log_level)

            # Provide server's a means of communicating readiness to clients. This is used during file proxying
            # to form a feedback loop between the proxy and client, that way the client doesn't ever exceed the
            # maximum channel capacity(i.e bandwidth) of it's connection to the proxy server.

            if message.startswith("notify:"):

                arguments = Primitives.parse_cmd(message)

                if arguments[0] == "something":
                    pass  # Do something about it

            # Disconnect some misbehaving node and pop it from network tuple
            if message.startswith("remove:"):

                address_to_remove = message[7:]

                try:
                    # Disconnect from remote node.
                    # Don't disconnect from localhost. That's what self.terminate is for.
                    if address_to_remove != Primitives.get_local_ip() and address_to_remove != "127.0.0.1":

                        # Lookup the socket of the address to remove
                        sock = self.lookup_socket(address_to_remove)

                        if sock:
                            Primitives.log("Remove -> Disconnecting from " + address_to_remove,
                                           in_log_level="Info")

                            connection_to_remove = (sock, address_to_remove)

                            Primitives.log(str("\tWho's connection is: " + str(connection_to_remove)),
                                           in_log_level="Debug")

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

                # Localhost needs to remove said node too! (see message propagation)
                localhost_conn = (localhost, "127.0.0.1")
                self.send(localhost_conn, no_prop + ":" + message, sign=False)

            # Start a network election which selects a suitable node to do some task
            if message.startswith("vote:"):
                import vote

                ongoing_election = self.read_nodestate(10)
                Primitives.log("(vote:) Ongoing election: " + str(ongoing_election), in_log_level="Debug")
                self.write_nodestate(nodeState, 10, True)   # set ongoing_election = True

                # Instead of making global changes to the nodeState, pass a new nodeState to vote
                # with the appropriate parameters changed...

                new_nodestate = vote.respond_start(message, nodeState, ongoing_election)
                self.overwrite_nodestate(new_nodestate)

            # Participate in a network election by entering as a candidate
            if message.startswith("campaign:"):
                # example message: campaign:do_stuff:01234566789

                arguments = Primitives.parse_cmd(message)

                ongoing_election = self.read_nodestate(10)

                if not ongoing_election:
                    # We probably received a campaign flag out of order(before a vote:). Let's start that election now.
                    # ------------------------------------------------------
                    # Intended vote flag: vote:reason (received out of order)
                    # Received campaign flag: campaign:reason:token (will suffice)
                    # Reconstruct the lost vote: from the campaign: arguments

                    Primitives.log("Received a campaign: flag out of order(i.e before the vote: flag)."
                                   "Attempting to initiate our election protocol with any information we"
                                   "can collect.", in_log_level="Warning")
                    os.chdir(original_path)
                    election_details = Primitives.parse_cmd(message)  # [reason, token]

                    # Before we (hopefully) receive a vote flag: the election list is empty. Populate it
                    campaign_tuple = tuple(election_details)
                    campaign_list = self.read_nodestate(8)

                    campaign_list.append(campaign_tuple)
                    self.write_nodestate(nodeState, 8, campaign_list)

                    self.broadcast(no_prop+":vote:"+str(election_details[0]), do_mesh_propagation=True)

                if ongoing_election:

                    election_details = Primitives.parse_cmd(message)  # [reason, token]

                    campaign_tuple = tuple(election_details)

                    campaign_list = self.read_nodestate(8)
                    campaign_list.append(campaign_tuple)

                    this_campaign_list = []

                    for item in campaign_list:

                        if item[0].startswith(arguments[0]):

                            this_campaign_list.append(item)

                    this_campaign_list = list(set(this_campaign_list))

                    Primitives.log(str(len(this_campaign_list)) + " nodes have cast votes for "+election_details[0])
                    # Wait for all votes to be cast
                    if len(this_campaign_list) == network_size:
                        campaign_ints = []

                        for campaign_tuple in campaign_list:
                            if campaign_tuple[0] == arguments[0]:
                                campaign_int = campaign_tuple[1]
                                campaign_ints.append(campaign_int)

                        winning_int = max(campaign_ints)
                        winning_reason = ""

                        for campaign_tuple in campaign_list:
                            if campaign_tuple[1] == winning_int:
                                winning_reason = campaign_tuple[0]

                        election_log_msg = str(winning_int) + " won the election for: " + winning_reason
                        Primitives.log(election_log_msg, in_log_level="Info")

                        this_campaign = self.read_nodestate(7)

                        if this_campaign == int(winning_int):
                            Primitives.log("We won the election for: " + winning_reason, in_log_level="Info")
                            elect_msg = self.prepare("elect:" + winning_reason + ":" + str(Primitives.get_local_ip()))
                            self.broadcast(elect_msg, do_mesh_propagation=True)

                            self.write_nodestate(nodeState, 11, True)  # set is_cluster_rep = True
                        else:
                            self.write_nodestate(nodeState, 11, False)  # set is_cluster_rep = False

                        # Cleanup
                        self.write_nodestate(nodeState, 8, [])  # Clear the campaign_list
                        self.write_nodestate(nodeState, 7, 0)   # reset this_campaign to 0
                        self.write_nodestate(nodeState, 10, False)  # clear ongoing_election

            # Elect the winning node of a network election to their position as cluster representative
            if message.startswith("elect:"):
                # elect:reason:representative

                # Parse arguments
                args = Primitives.parse_cmd(message)

                reason = args[0]
                new_leader = args[1]

                # Index of tuple containing winning node
                election_list = self.read_nodestate(9)
                index = Primitives.find_election_index(election_list, reason)

                new_election_list = Primitives.set_leader(election_list, index, new_leader)

                self.write_nodestate(nodeState, 9, new_election_list)  # Update the election list

                election_winner_msg = str(new_leader) + " won the election for:" + reason
                Primitives.log(election_winner_msg, in_log_level="Info")

                if reason.startswith('discovery-'):
                    os.chdir(original_path)
                    import discover

                    # Remove any previous discovery elections from the election list.
                    # This allows network bootstrapping to occur multiple times without reinitializing

                    for _election_tuple in new_election_list:
                        _reason = _election_tuple[0]
                        _index_in_new_election_list = new_election_list.index(_election_tuple)

                        if _reason != reason:
                            new_election_list.remove(_election_tuple)

                    self.write_nodestate(nodeState, 9, new_election_list)

                    op_id = reason[10:]
                    is_cluster_rep = self.read_nodestate(11)
                    self.write_nodestate(nodeState, 10, False)  # Set ongoing_election = False

                    Primitives.log("(end of vote:) Ongoing election: "+str(self.read_nodestate(10)),
                                   in_log_level="Debug")

                    Primitives.log(str(new_election_list), in_log_level="Debug")

                    discover.respond_start(net_tuple, op_id, is_cluster_rep)

            # Write the remote addresses of all connected nodes to the pagefile established by $discover
            if message.startswith("sharepeers:"):
                os.chdir(original_path)
                import discover

                new_module_loaded = "discover"
                self.write_nodestate(nodeState, 4, new_module_loaded)  # set module_loaded = "discover"

                arguments = Primitives.parse_cmd(message)  # arguments[0] = op_id = name of pagefile

                op_id = arguments[0]

                # Get a list of all remote addresses
                _data = Primitives.get_local_ip()
                addresses = [item[1] for item in net_tuple]
                _data += "\n" + '\n'.join(addresses)

                # Write it to page [op_id]
                self.write_to_page(op_id, _data, signing=False)

                # Callback to discover module
                discover.start(net_tuple, op_id, self.read_nodestate(11))

            # Ring Network --> Fully-Complete/Mesh network bootstrapping routine
            if message.startswith("bootstrap:"):
                arguments = Primitives.parse_cmd(message)

                # arguments[0] = network architecture to boostrap into (e.x "mesh")
                # arguments[1] = c_ext

                election_list = self.read_nodestate(9)
                net_architecture = arguments[0]
                c_ext = int(arguments[1])

                # Find peer discovery output pagefile
                hosts_pagefile = ''.join([item[0][10:] for item in election_list if item[0][:10] == "discovery-"])
                Primitives.log("Hosts pagefile is " + hosts_pagefile + ".bin", in_log_level="Info")

                print("Output node: " + str(output_node))

                print(str(election_list))

                try:
                    pagefile = open("../inter/mem/" + hosts_pagefile + ".bin", "r+")
                    potential_peers = pagefile.readlines()
                    pagefile.close()

                except FileNotFoundError:
                    Primitives.log(hosts_pagefile+".bin" + " does not exist.", in_log_level="Warning")
                    potential_peers = None

                chosen_peers = []

                if potential_peers:
                    for peer in potential_peers:
                        if peer == Primitives.get_local_ip() + "\n":  # Do not try to pick ourselves as a remote node
                            potential_peers.remove(peer)

                if potential_peers:
                    if net_architecture == "mesh":
                        print("Network tuple:")
                        print(str(net_tuple))

                        this_node = (localhost, "127.0.0.1")

                        # Disconnect from everything other than localhost
                        for peer in net_tuple:

                            if peer != this_node:
                                self.disconnect(peer)
                                net_tuple = self.read_nodestate(0)  # Refresh the network tuple after disconnecting

                            else:
                                pass  # Don't disconnect from localhost

                        # Select remote peers to bootstrap with
                        for i in range(0, c_ext):
                            chosen_peer = random.choice(potential_peers)
                            potential_peers.remove(chosen_peer)
                            chosen_peers.append(chosen_peer.strip("\n"))

                        Primitives.log("Disassociation successful. Ready for bootstrap...", in_log_level="Info")

                        # Bootstrap!
                        for peer_address in chosen_peers:
                            external_connection = (socket.socket(), peer_address)
                            self.connect(external_connection, peer_address, PORT)

                        # Great, bootstrapping was successful
                        # Set global message propagation mode to mesh
                        do_mesh_propagation = self.read_nodestate(12)

                        if not do_mesh_propagation:
                            do_mesh_propagation = True
                            self.write_nodestate(nodeState, 12, do_mesh_propagation)

            # Append message signature to the message list, or in the case of sig=no_prop, do nothing.
            if sig != no_prop and propagation_allowed:
                new_message_list = list(message_list)
                new_message_list.append(sig)
                self.write_nodestate(nodeState, 1, new_message_list)
                # End of respond()

                # Propagate the message to the rest of the network.
                Primitives.log(str('Broadcasting: ' + full_message), in_log_level="Debug")
                self.broadcast(full_message)

    def listen(self, connection):
        # Listen for incoming messages and call self.respond() to respond to them.
        # Also, deal with disconnections as they are most likely to throw errors here.
        # Returns nothing.

        def listener_thread(conn):
            in_sock = conn[0]
            terminated = self.read_nodestate(3)
            listener_terminated = False  # Terminate when set

            while not listener_terminated and not terminated:
                incoming = Primitives.receive(conn)
                raw_message = incoming
                try:
                    if incoming:
                        self.respond(conn, raw_message)

                except ArithmeticError:   # DEBUG TypeError
                    conn_severed_msg = str("Connection to " + str(in_sock)
                                           + "was severed or disconnected."
                                           + "(TypeError: listen() -> listener_thread()")
                    Primitives.log(conn_severed_msg, in_log_level="Warning")

                    self.disconnect(conn)
                    listener_terminated = True

                if incoming == 1:
                    self.disconnect(conn)
                    conn_not_existent_msg = str("Connection to " + str(in_sock) +
                                                "doesn't exist, terminating listener_thread()")
                    Primitives.log(conn_not_existent_msg, in_log_level="Warning")
                    listener_terminated = True

        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(connection,), name='listener_thread').start()

    def terminate(self):
        global localhost
        # Disconnect from the network and exit the client cleanly.
        # Returns 0 -> int (duh)

        net_tuple = self.read_nodestate(0)
        page_list = self.read_nodestate(6)

        Primitives.log("Safely terminating our connections...", in_log_level="Warning")

        index = 0
        for file in page_list:
            Primitives.log("Closing pages..", in_log_level="Info")
            file.close()

            try:
                os.remove(file.name)

            except FileNotFoundError:
                Primitives.log("Not removing non-existent page")

            Primitives.log(str("Terminating connection to "), in_log_level="Info")

        for connection in net_tuple:
            address = connection[1]
            Primitives.log(str("Terminating connection to " + address), in_log_level="Info")
            self.disconnect(connection, disallow_local_disconnect=False)
            localhost.close()

            index += 1

        Primitives.log("Quietly Dying...")
        self.write_nodestate(nodeState, 3, True)  # Set terminated = True

        # noinspection PyProtectedMember
        os._exit(0)  # kill oneself with passion

    def initialize(self, port=3705, net_architecture="complete", remote_addresses=None, command_execution=False,
                   default_log_level="Debug", modules=None, net_size=0):

        # Initialize the client, set any global variable that need to be set, etc.

        global allow_command_execution
        global localhost
        global log_level
        global PORT
        global Primitives
        global sub_node
        global SALT
        global ADDR_ID
        global network_architecture
        global network_size
        global output_node

        # Global variable assignment
        PORT = port
        allow_command_execution = command_execution
        log_level = default_log_level
        network_architecture = net_architecture
        network_size = net_size

        if remote_addresses:
            output_node = random.choice(remote_addresses)
        else:
            output_node = None

        Primitives = primitives.Primitives(sub_node, log_level)
        SALT = secrets.token_hex(16)
        ADDR_ID = Primitives.gen_addr_id(SALT)

        new_loaded_modules = []

        # Import loaded modules
        for item in modules:
            import_str = "import " + item
            new_loaded_modules.append(item)
            exec(import_str)

        self.write_nodestate(nodeState, 4, new_loaded_modules)

        # Stage 0
        Primitives.log("Initializing...", in_log_level="Info")
        localhost_connection = (localhost, '127.0.0.1')

        try:
            self.connect(localhost_connection, 'localhost', port, local=True)

            Primitives.log("Connection to localhost successful", in_log_level="Info")
            Primitives.log("Starting listener on localhost...", in_log_level="Info")

            self.listen(localhost_connection)

        except ConnectionRefusedError:

            Primitives.log("Connection to localhost unsuccessful; check that your server is "
                           "initialized, and try again later.", in_log_level="Warning")
            quit(1)

        except FileNotFoundError:
            pass

        Primitives.log("Attempting to connect to remote server(s)... (Initiating stage 1)",
                       in_log_level="Info")

        # Stage 1
        if remote_addresses:

            for remote_address in remote_addresses:
                # Join the network if one already exists...

                sock = socket.socket()

                try:
                    connection = (sock, remote_address)
                    self.connect(connection, remote_address, port)

                    Primitives.log(str("Starting listener on " + remote_address), in_log_level="Info")
                    self.listen(connection)

                    if network_architecture == "complete":
                        self.send(connection, no_prop + ":echo", sign=False)  # TODO: why?

                except ConnectionRefusedError:
                    Primitives.log("Unable to connect to remove server; Failed to bootstrap.",
                                   in_log_level="Warning")
        else:
            Primitives.log("Initializing with no remote connections...", in_log_level="Info")
