# Python 3.6.2
import socket
import struct
import threading
import multiprocessing
import datetime
import os
import random
import sys
import secrets
from time import sleep
from hashlib import sha3_224

sys.path.insert(0, '../inter/')
sys.path.insert(0, '../misc/')
import primitives

# Globals
localhost = socket.socket()
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Nobody likes TIME_WAIT-ing. Add SO_REUSEADDR.

# State
election_list = []   # [(reason, representative), (another_reason, another_representative)]
campaign_list = []  # [int, another_int, etc.]
file_list = []  # [(file_size, path, checksum, proxy), (file_size2, path2, checksum2, proxy2), etc.]
our_campaign = 0  # An integer between 0 and 2^128 (see voting algorithm)
dictionary_size = 0  # Temporarily store the dictionary_size value while we sync: (WPABruteForce)
network_tuple = ()  # ((socket, address), (another_socket, another_address))
message_list = []  # [message_hash, another_msg_hash, etc.]
page_list = []  # temporary file objects to close and delete on stop()
page_ids = []  # Used by some modules
file_proxy = ""  # Temporarily store the most recently voted file proxy until it is appended to the file_list.
terminated = False
cluster_rep = False
ongoing_election = False
module_loaded = ""  # Current module being executed


# Defaults and arguments and things to be set by self.initialize(). Not state.
PORT = 3705
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]
connecting_to_server = False
allow_file_storage = True
log_level = ""  # "Debug", "Info", or "Warning"; To be set by init
sub_node = "Client"
no_prop = "ffffffffffffffff"  # True:[message] = No message propagation.
SALT = None  # Will be set to a 128-bit hexadecimal token(by self.init) for making address identifiers
ADDR_ID = None  # Another 128-bit hexadecimal token that wil be salted with SALT, and set by init()
original_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(original_path)
sys.path.insert(0, '../inter/modules/')
sys.path.insert(0, '../server/')

# Will be reset later
Primitives = primitives.Primitives(sub_node, log_level)
network_architecture = ""
loaded_modules = []  # List of all modules loaded


class Client:

    @staticmethod
    def prepare(message):
        """ Assign unique hashes to messages ready for transport.
            Returns (new hashed message) -> str """

        out = ""

        # Assign a timestamp
        timestamp = str(datetime.datetime.utcnow())
        stamped_message = timestamp+message
        out += stamped_message

        # Generate the hash and append the message to it
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = sig + ":" + message
        return out

    @staticmethod
    def lookup_socket(address, ext_net_tuple=None):  # TODO: optimize me
        """Brute force search the network tuple for a socket associated with a given address.
            Return socket object if found.
            Returns 0(-> int) if not found
        """
        if ext_net_tuple:
            net_tuple = ext_net_tuple
        else:
            net_tuple = network_tuple

        for item in net_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

        return 0  # Socket not found

    @staticmethod
    def lookup_address(in_sock, ext_net_tuple=None):  # TODO: optimize me
        """Brute force search the network tuple for an address associated with a given socket.
            Return a string containing an address if found.
            Returns 0 (-> int) if not found
        """
        if ext_net_tuple:
            net_tuple = ext_net_tuple
        else:
            net_tuple = network_tuple

        for item in net_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

        return 0  # Address not found

    @staticmethod
    def permute_network_tuple():
        """ Permute the network tuple. Repetitive permutation after each call
            of respond() functionally allows the network to inherit many of the anonymous
            aspects of a mixing network. Packets are sent sequentially in the order of the
            network tuple, which when permuted, thwarts many timing attacks. ''
            Doesn't return """

        global network_tuple

        network_list = list(network_tuple)

        cs_prng = random.SystemRandom()
        cs_prng.shuffle(network_list)

        # Tuples are immutable. We have to overwrite the exiting one to 'update' it.
        new_network_tuple = tuple(network_list)
        network_tuple = new_network_tuple

    @staticmethod
    def append(in_socket, address):
        """ Append a given connection object(tuple of (socket, address)) to the network tuple.
            Doesn't return """

        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        connection = (in_socket, address)
        network_list.append(connection)

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)
        print("\n\n\n" + str(network_tuple))

    @staticmethod
    def remove(connection):
        """ Remove a given connection object(tuple of (socket, address)) from the network tuple.
            Doesn't return """

        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        # Identify and remove said connection
        try:
            index = network_list.index(connection)
            network_list.pop(index)

        # Connection not in network tuple, or socket is [closed]
        except ValueError:
            Primitives.log(str("Not removing non-existent connection: " + str(connection)), in_log_level="Warning")
            return None

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def connect(self, connection, address, port, local=False):
        """ Connect to a remote server and handle the connection(i.e append it).
            Doesn't return. """

        global connecting_to_server
        sock = connection[0]

        # Make a real copy of the network tuple
        # Then append our new connection (will be removed if connection fails)
        quasi_network_tuple = tuple(network_tuple)
        self.append(sock, address)

        # Don't connect to an address we're already connected to.
        if connection in quasi_network_tuple:

            not_connecting_msg = str("Not connecting to " + connection[1],
                                     "We're already connected.")

            Primitives.log(not_connecting_msg, in_log_level="Warning")
            self.remove((sock, address))

        # Do connect to nodes we are not already connected to
        else:
            # Also don't try to connect to multiple servers at once in the same thread.
            if not connecting_to_server:
                # connecting_to_server is a mutex which prevents this function
                # from making external connections when it's not supposed to.
                connecting_to_server = True

                if not local:

                    Primitives.log(str("Connecting to " + address), in_log_level="Info")
                    sock.connect((address, port))
                    Primitives.log("Successfully connected.", in_log_level="Info")
                    connecting_to_server = False

                elif local:
                    self.remove((sock, address))

                    Primitives.log("Connecting to localhost server...", in_log_level="Info")

                    sock.connect(("127.0.0.1", port))
                    self.append(sock, "127.0.0.1")
                    # The socket object we apppended earlier was automatically
                    # destroyed by the OS because connections to 0.0.0.0 are illegal...
                    # Connect to localhost with raddr=127.0.0.1...


                    Primitives.log("Successfully connected to localhost server", in_log_level="Info")
                    connecting_to_server = False

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

    def broadcast(self, message):
        Primitives.log("Permuting the network tuple", in_log_level="Info")
        self.permute_network_tuple()
        for connection in network_tuple:
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
        """ Write data to a given pagefile by ID."""

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

        this_page = open(file_path, "a+")
        this_page.write(data_line)
        this_page.close()

    def respond(self, connection, msg):
        """ We received a message, reply with an appropriate response.
            Doesn't return. """

        # Eww... I smell a global state lurking somewhere.
        global message_list
        global cluster_rep
        global page_list
        global election_list
        global campaign_list
        global file_list
        global our_campaign
        global ongoing_election
        global page_ids
        global ADDR_ID
        global file_proxy
        global dictionary_size
        global network_architecture

        full_message = str(msg)
        message = full_message[17:]  # Message without signature
        sig = full_message[:16]  # Just the signature
        address = connection[1]

        if address == "127.0.0.1":
            Primitives.log("Received message from 127.0.0.1; This is a violation of protocol; "
                           "replacing address with Local IP.", in_log_level="Debug")
            # Replying to localhost is strictly disallowed. Replace localhost with actual local IP.
            address = Primitives.get_local_ip()

        # Introduce additional network mixing anonymity by introducing a random delay makes it difficult or
        # impossible to derive message paths through timing analysis alone.

        sleep(random.uniform(0.008, 0.05))  # 8mS - 50mS

        # Don't respond to messages we've already responded to.
        if sig in message_list:

            not_responding_to_msg = str("Not responding to " + sig)
            Primitives.log(not_responding_to_msg, in_log_level="Debug")

        # Do respond to messages we have yet to respond to.
        elif sig not in message_list or sig == no_prop:

            # e.x "Client -> Received: echo (ffffffffffffffff) from: 127.0.0.1"
            message_received_log = str('Received: ' + message
                                       + " (" + sig + ")" + " from: " + address)

            Primitives.log(message_received_log, in_log_level="Info")

            if message == "echo":
                """ Simple way to test our connection to a given node."""

                Primitives.log("echoing...", in_log_level="Info")

                if network_architecture == "complete":
                    self.send(connection, no_prop + ':' + message, sign=False)  # If received, send back

            if message == "stop":
                """ instruct all nodes to disconnect from each other and exit cleanly."""

                # Inform localhost to follow suit.
                localhost_connection = (localhost, "127.0.0.1")
                self.send(localhost_connection, "stop")  # TODO: should we use no_prop here?

                # Do so ourselves
                self.terminate()

            if message.startswith("ConnectTo:"):

                """ConnectTo: Instructs external clients to connect to remote servers.
                ConnectTo: is sent by each node being connected to when a new node joins the network, with one
                ConnectTo: flag per node in their network table], instructing the new node to connect to 
                [each node in their network table]. As long as all nodes respond to ConnectTo: flags,
                (if network_architecture = "complete" in init_client/init_server)
                the network will always be fully-connected.
                
                Elsewhere in the documentation and code, this bootstrapping mechanism is
                referred to as "address propagation"
                """

                # remove the 'ConnectTo:' flag from the message, leaving only the external address to connect to.
                connect_to_address = message[10:]

                # lookup_socket will return 0 if we're not already connected to said address (above)
                connection_status = self.lookup_socket(connect_to_address)
                Primitives.log(str(network_tuple), in_log_level="Debug")

                # If we're not already connected and making this connection won't break anything, connect now.
                if connection_status == 0:

                    overide_localhost_failsafe = False

                    remote_adress_is_localhost = connect_to_address == Primitives.get_local_ip() or \
                                                  connect_to_address == "127.0.0.1"

                    # Don't re-connect to localhost unless we're not connected yet.
                    # All kinds of bad things happen if you do.
                    if remote_adress_is_localhost and not overide_localhost_failsafe:

                            not_connecting_msg = str("Not connecting to " + connect_to_address + "; That's localhost :P")
                            Primitives.log(not_connecting_msg, in_log_level="Warning")

                    else:

                        mesh_network = (network_architecture == "mesh")  # True if network architecture is mesh
                        received_packet_from_localhost = (address == "127.0.0.1" or address == Primitives.get_local_ip())

                        print('\n\n')
                        print("\tNetwork Architecture: "+network_architecture)
                        print("\tNetwork Architecture is mesh: "+str(mesh_network))
                        print("\tRemote Address is Localhost: " + str(remote_adress_is_localhost))
                        print("\tReceived packet from Localhost: " + str(received_packet_from_localhost))
                        print("\n\n")

                        if (mesh_network and received_packet_from_localhost) or not mesh_network:

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

            if message.startswith('exec:'):
                # Assuming allow_command_execution is set, execute arbitrary UNIX commands in their own threads.
                if allow_command_execution:
                    command = message[5:]
                    Primitives.log(str("executing: " + command), in_log_level="Info")

                    # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                    # non-isolated fork of a process. That's very dangerous.
                    command_process = multiprocessing.Process(target=self.run_external_command,
                                                              args=(command,), name='Cmd_Thread')
                    command_process.start()

                # allow_command_execution is not set, don't execute arbitrary UNIX commands from the network.
                else:
                    Primitives.log(("Not executing command: ", message[5:]), in_log_level="Info")

            if message.startswith("newpage:"):
                """ Create a new pagefile that we'll presumably do some 
                parallel or distributed operations with.
                e.x newpage:(64-bit identifier provided by sender)"""

                page_id = message[8:]
                new_filename = str("../inter/mem/" + page_id + ".bin")
                Primitives.log("Creating new page with id: " + str(page_id), in_log_level="Info")

                os.chdir(original_path)
                newpage = open(new_filename, "a+")
                page_list.append(newpage)

            if message.startswith("corecount:"):
                global module_loaded
                import corecount

                module_loaded = "corecount"
                corecount.respond_start(page_ids, message)

            if message.startswith("fetch:"):
                """ Broadcast the contents of [page id] to maintain distributed memory """

                page_id = message[6:]

                # Read contents of page
                os.chdir(original_path)
                pagefile = open("../inter/mem/" + page_id + ".bin", "r+")

                page_lines = pagefile.readlines()

                # Don't sync comments
                for string in page_lines:
                    if string[:1] == "#":
                        page_lines.remove(string)

                page_contents = ''.join(page_lines)

                sync_msg = (no_prop + ":" + "sync:" + page_id + ":" + page_contents)
                self.broadcast(sync_msg)

            if message.startswith("sync:"):
                """ Update our pagefile with data from another node (such as another node's completed work)
                Translation: write arbitrary data to page [page id] 
                Syntax: sync:(page id):(data)
                """

                os.chdir(original_path)
                page_id = message[5:][:16] # First 16 bytes after removing the 'sync:' flag
                data = message[22:]

                Primitives.log("Syncing " + data + " into page:" + page_id, in_log_level="Info")

                file_path = "../inter/mem/" + page_id + ".bin"

                file_exists = False

                try:
                    existing_pagelines = open(file_path, "r+").readlines()
                    file_exists = True

                except FileNotFoundError:
                    Primitives.log("Cannot open a non-existent page")
                    existing_pagelines = []  # Stop my PyCharm from telling me this is referenced before assignment

                if file_exists:
                    duplicate = False
                    local = False

                    # How do we sort out duplicates?
                    for line in existing_pagelines:
                        if line == data and line[:32]:
                            duplicate = True
                            Primitives.log("Not writing duplicate data into page " + page_id)
                            break

                    if not duplicate:
                        data_id = data[:16]
                        local_id = sha3_224(Primitives.get_local_ip().encode()).hexdigest()[:16]
                        if data_id == local_id:
                            # Don't re-write data from ourselves. We already did that with 'corecount'.
                            print("Not being hypocritical in page " + page_id)
                            local = True

                        if not local:
                            if data == "" or data == " " or data == "\n":
                                pass

                            else:
                                print("Writing " + data + "to page " + page_id)
                                self.write_to_page(page_id, data, signing=False)

                    # https://stackoverflow.com/a/1216544
                    # https://stackoverflow.com/users/146442/marcell
                    # The following two lines of code are the work were written by "Marcel" from StackOverflow.

                    # Cleanup after sync

                    # Remove duplicate lines
                    unique_lines = set(open(file_path).readlines())
                    open(file_path, 'w').writelines(set(unique_lines))

                    # Remove any extra newlines
                    raw_lines = list(set(open(file_path).readlines()))

                    newlines = [raw_line for raw_line in raw_lines
                                if raw_line != "\n" and raw_line[:2] != "##"]

                    open(file_path, 'w').writelines(set(newlines))

                    print(len(network_tuple))

                    # Wait for each node to contribute before doing module-specific I/O
                    Primitives.log("\n\t" + str(len(newlines)) + " Node(s) have contributed to the network."
                                                                 "\n The network tuple(+1) is of length: "
                                   + str(len(network_tuple) + 1), in_log_level="Debug")

                    if len(newlines) == len(network_tuple)+1:
                        # We've received contributions from every node on the network.
                        # Now do module-specific I/O
                        if module_loaded == "corecount":
                            os.chdir(original_path)
                            import corecount
                            corecount.start(page_id, raw_lines, newlines)
                            module_loaded = ""

                        elif module_loaded == "WPABruteForce":
                            os.chdir(original_path)
                            import WPABruteforce
                            WPABruteforce.start(page_id, raw_lines, dictionary_size, ADDR_ID)

            if message.startswith("file:"):
                # file:(64-bit file hash):(32-bit file length):(128-bit origin address identifier)
                Primitives.log("Not doing anything with file request because they are not implemented yet.")
                message_to_parse = message[5:]  # Remove "file:" from message string so we can parse it correctly.
                file_hash = message_to_parse[:16]
                file_length = message_to_parse[17:][:8]
                origin_addr_id = message_to_parse[26:]

                Primitives.log("Our Address Identifier: "+ADDR_ID, in_log_level="Debug")
                Primitives.log("Received message destined for Address Identifier: "+origin_addr_id,
                               in_log_level="Debug")
                Primitives.log("Checksum: " + file_hash)
                Primitives.log("File Size: "+str(file_length))

                # ... If applicable, affirm the file request, and hopefully receive data through the proxy.

            if message.startswith("init_file:"):
                os.chdir(original_path)
                import inject
                import file
                injector = inject.NetworkInjector()
                arguments = injector.parse_cmd(message)
                file_path = arguments[0]
                file_size = arguments[1]
                checksum = str(file.md5sum(file_path))
                election_reason = 'dfs-'+checksum

                file_tuple = (file_size, file_path, checksum, "TBD")
                file_list.append(file_tuple)

                # Vote a proxy
                Primitives.log("Voting a proxy", in_log_level="Info")

                vote_msg = "vote:"+election_reason
                self.broadcast(self.prepare(vote_msg))

                # Will be continued in self.init_file(stage=1), called during the elect: flag

            # Provide server's a means of communicating readiness to clients. This is used during file proxying
            # to form a feedback loop between the proxy and client, that way the client doesn't ever exceed the
            # maximum channel capacity(i.e bandwidth) of it's connection to the proxy server.
            if message.startswith("notify:"):
                import inject
                import file
                Injector = inject.NetworkInjector()

                arguments = Injector.parse_cmd(message)
                if arguments[0] == "proxy_ready":
                    # Proxy is ready for data; pass control back to file module

                    file_checksum = arguments[1]
                    Primitives.log("Proxy is ready", in_log_level="Info")
                    Primitives.log("File checksum according to Proxy: "+arguments[1], in_log_level="Debug")
                    proxy_addr = Primitives.find_representative(election_list, "dfs-"+arguments[1])
                    file.respond_start(proxy_addr, file_checksum, file_list, network_tuple, init=True)

                if arguments[0] == "next_packet":
                    # Proxy is ready for data; pass control back to file module. (Feedback Loop)
                    Primitives.log("Next packet...", in_log_level="Info")
                    file_checksum = arguments[1]
                    proxy_addr = Primitives.find_representative(election_list, "dfs-"+arguments[1])
                    file.respond_start(proxy_addr, file_checksum, file_list, network_tuple, init=False)

            # Disconnect from some misbehaving node and pop it from out network tuple
            # example message: remove:192.168.2.3
            if message.startswith("remove:"):

                address_to_remove = message[7:]

                try:
                    # Disconnect from remote node.
                    # Don't disconnect from localhost. That's what self.terminate is for.
                    if address_to_remove != Primitives.get_local_ip() and address_to_remove != "127.0.0.1":

                        sock = self.lookup_socket(address_to_remove)

                        if sock:
                            Primitives.log("Remove -> Disconnecting from " + address_to_remove,
                                           in_log_level="Info")

                            # lookup the socket of the address we want to remove
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
                    pass

                # Localhost needs to remove said node too! (see message propagation)
                localhost_conn = (localhost, "127.0.0.1")
                self.send(localhost_conn, no_prop+":"+message, sign=False)

            if message.startswith("vote:"):
                Primitives.log("Ongoing election: "+str(ongoing_election), in_log_level="Debug")

                if not ongoing_election:
                    ongoing_election = True
                    reason = message[5:]

                    election_tuple = (reason, "TBD")
                    election_list.append(election_tuple)

                    campaign_int = random.randint(1, 2**128)
                    our_campaign = campaign_int

                    Primitives.log("Campaigning for "+str(campaign_int), in_log_level="Info")
                    campaign_msg = self.prepare("campaign:"+reason+":"+str(campaign_int))
                    self.broadcast(campaign_msg)

            if message.startswith("campaign:"):
                # example message: campaign:do_stuff:01234566789

                if not ongoing_election:
                    # We probably received a campaign flag out of order(before a vote:). Let's start that election now.
                    # ------------------------------------------------------
                    # Intended vote flag: vote:reason (received out of order)
                    # Received campaign flag: campaign:reason:token (will suffice)
                    # See where I'm going now?

                    Primitives.log("Received a campaign: flag out of order(i.e before the vote: flag)."
                                   "Attempting to initiate our election protocol with any information we"
                                   "can collect.", in_log_level="Warning")
                    os.chdir(original_path)
                    import inject
                    Injector = inject.NetworkInjector()

                    election_details = Injector.parse_cmd(message)  # [reason, token]

                    # Before we (hopefully) receive a vote flag: the elction list is empty. Populate it
                    campaign_tuple = tuple(Injector.parse_cmd(message))
                    campaign_list.append(campaign_tuple)
                    print(str(campaign_list))

                if ongoing_election:
                    import inject
                    Injector = inject.NetworkInjector()

                    campaign_tuple = tuple(Injector.parse_cmd(message))
                    campaign_list.append(campaign_tuple)

                    print(str(campaign_list))

                    # Wait for all votes to be cast
                    if len(campaign_list) == len(network_tuple)+1:
                        campaign_ints = []

                        for campaign_tuple in campaign_list:
                            campaign_int = campaign_tuple[1]
                            campaign_ints.append(campaign_int)

                        winning_int = max(campaign_ints)
                        winning_reason = ""

                        for campaign_tuple in campaign_list:
                            if campaign_tuple[1] == winning_int:
                                winning_reason = campaign_tuple[0]

                        election_log_msg = str(winning_int) + " won the election for: " + winning_reason
                        Primitives.log(election_log_msg, in_log_level="Info")

                        if our_campaign == int(winning_int):
                            Primitives.log("We won the election for: "+winning_reason, in_log_level="Info")
                            elect_msg = self.prepare("elect:"+winning_reason+":"+str(Primitives.get_local_ip()))
                            self.broadcast(elect_msg)

                            cluster_rep = True
                        else:
                            cluster_rep = False

                        # Cleanup
                        campaign_list = []
                        our_campaign = 0

            if message.startswith("elect:"):
                # elect:reason:representative
                import inject

                # Parse arguments
                Injector = inject.NetworkInjector()
                args = Injector.parse_cmd(message)

                reason = args[0]
                new_leader = args[1]

                # Index of tuple containing winning node
                index = Primitives.find_election_index(election_list, reason)

                election_list = Primitives.set_leader(election_list, index, new_leader)
                ongoing_election = False

                election_winner_msg = str(new_leader) + " won the election for:" + reason
                Primitives.log(election_winner_msg, in_log_level="Info")

                # We're electing a proxy for distributed file storage
                if reason.startswith('dfs-'):
                    print("File proxy: "+new_leader)
                    file_proxy = new_leader
                    file_checksum = reason[4:]

                    if Primitives.find_file_tuple(file_list, file_checksum) != -1:
                        import file
                        file_tuple = Primitives.find_file_tuple(file_list, file_checksum)
                        file_index = file_list.index(file_tuple)
                        file_list[file_index] = Primitives.set_file_proxy(file_checksum, file_list, file_proxy)

                        # Pass control to the file module
                        file.start(1, new_leader, file_checksum, localhost, file_list, network_tuple)

                print("\n")
                print(election_list)  # DEBUG
                print("\n")

            if message.startswith("benchmark:"):
                module_loaded = "WPABruteForce"
                os.chdir(original_path)
                import inject
                import WPABruteforce
                arguments = inject.NetworkInjector().parse_cmd(message)

                if arguments[0] == "WPA":

                    def do_benchmark_and_continue(in_arguments):
                        global dictionary_size
                        global score
                        global page_ids

                        page_hash = arguments[2]
                        dict_size = arguments[1]
                        if page_hash not in page_ids:
                            page_ids.append(page_hash)
                            score = WPABruteforce.do_wpa_benchmark()
                            WPABruteforce.respond_start(score, page_hash, ADDR_ID, network_tuple)

                        else:
                            Primitives.log("Not initiating a duplicate benchmark")

                    dictionary_size = arguments[1]
                    new_process = multiprocessing.Process(target=do_benchmark_and_continue,
                                                          args=(arguments, ), name='WPA Benchmark Thread')
                    new_process.daemon = True
                    new_process.start()
                    Primitives.log("Initiating benchmark...", in_log_level="Info")

            # Append signature(hash) to the message list, or in the case of sig=no_prop, do nothing.
            if sig != no_prop:
                message_list.append(sig)

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
            global terminated
            listener_terminated = False  # Terminate when set

            while not listener_terminated and not terminated:
                incoming = Primitives.receive(conn)
                raw_message = incoming
                try:
                    if incoming:
                        self.respond(conn, raw_message)

                except TypeError:
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
        # Disconnect from the network and exit the client cleanly.
        # Returns 0 -> int (duh)

        global terminated
        global network_tuple
        global page_list

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

        for connection in network_tuple:
            address = connection[1]
            Primitives.log(str("Terminating connection to " + address), in_log_level="Info")
            self.disconnect(connection, disallow_local_disconnect=False)
            index += 1

        Primitives.log("Quietly Dying...")
        terminated = True
        return 0

    def initialize(self, port=3705, net_architecture="complete",
                   remote_addresses=None, command_execution=False,
                   file_storage=True, default_log_level="Debug", modules=None):

        # Initialize the client, set any global variable that need to be set, etc.

        global allow_command_execution
        global allow_file_storage
        global localhost
        global log_level
        global PORT
        global loaded_modules
        global Primitives
        global sub_node
        global SALT
        global ADDR_ID
        global network_architecture

        # Global variable assignment
        PORT = port
        allow_command_execution = command_execution
        allow_file_storage = file_storage
        log_level = default_log_level
        network_architecture = net_architecture

        Primitives = primitives.Primitives(sub_node, log_level)
        SALT = secrets.token_hex(16)
        ADDR_ID = Primitives.gen_addr_id(SALT)

        for item in modules:
            import_str = "import " + item
            loaded_modules.append(item)
            exec(import_str)

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
                # Bootstrap into the network

                sock = socket.socket()

                try:
                    connection = (sock, remote_address)
                    self.connect(connection, remote_address, port)

                    Primitives.log(str("Starting listener on " + remote_address), in_log_level="Info")
                    self.listen(connection)

                    if network_architecture == "complete":
                        self.send(connection, no_prop+":echo", sign=False)  # WIP

                except ConnectionRefusedError:
                    Primitives.log("Unable to connect to remove server; Failed to bootstrap.",
                             in_log_level="Warning")
        else:
            Primitives.log("Initializing with no remote connections...", in_log_level="Info")
