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
file_list = []  # (file_size, path, checksum, proxy)
our_campaign = 0  # An integer between 0 and 2^128
network_tuple = ()  # ((socket, address), (another_socket, another_address))
message_list = []
page_list = []  # temporary file objects to close on stop
page_ids = []  # Used by some modules
file_proxy = ""
terminated = False
cluster_rep = False
ongoing_election = False

no_prop = "ffffffffffffffff"  # True:[message] = No message propagation.
loaded_modules = []  # List of all modules loaded
module_loaded = ""  # Current module being executed

original_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(original_path)
sys.path.insert(0, '../inter/modules/')

# To be (re)set by init()
PORT = 3705
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]
connecting_to_server = False
allow_file_storage = True
log_level = ""  # "Debug", "Info", or "Warning"; To be set by init
sub_node = "Client"
SALT = None  # Will be set to a 128-bit hexadecimal token(by self.init) for making address identifiers
ADDR_ID = None  # Another 128-bit hexadecimal token that wil be salted with SALt, and set by init()
Primitives = primitives.Primitives(log_level, sub_node)


class Client:

    @staticmethod
    def log(log_message, in_log_level='Warning', subnode="Client"):
        """ Process and deliver program output in an organized and
        easy to read fashion. Never returns. """

        # input verification
        levels = ["Debug", "Info", "Warning"]

        allowable_levels = []
        allow_further_levels = False  # Allow all levels after the input.

        for level in levels:
            if allow_further_levels:
                allowable_levels.append(level)

            if level == log_level:
                allowable_levels.append(level)
                allow_further_levels = True

        if in_log_level not in levels or in_log_level not in allowable_levels:
            pass

        else:
            print(subnode, "->", in_log_level + ":", log_message)

    def get_local_ip(self):
        """Creates a temporary socket and connects to subnet,
           yielding our local address. Returns: (local ip address) -> str """

        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            temp_socket.connect(('10.255.255.0', 0))

            # Yield our local address
            local_ip = temp_socket.getsockname()[0]

        except OSError:
            # Connect refused; there is likely no network connection.
            self.log("Failed to identify local IP address. No network connection detected.",
                     in_log_level="Warning")
            local_ip = "127.0.0.1"

        finally:
            temp_socket.close()

        return local_ip

    @staticmethod
    def prepare(message):
        """ Assign unique hashes to messages ready for transport.
            Returns (new hashed message) -> str """

        out = ""
        timestamp = str(datetime.datetime.utcnow())
        out += timestamp
        out += message
        sig = sha3_224(out.encode()).hexdigest()[:16]
        out = sig + ":" + message
        return out

    @staticmethod
    def lookup_socket(address, ext_net_tuple=None):  # TODO: optimize me
        """Brute force search the network tuple for a socket associated with a given address.
            Return socket object if found.
            Returns 0(-> int) id not found
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

    def remove(self, connection):
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
            self.log(str("Not removing non-existent connection: " + str(connection)),
                     in_log_level="Warning")
            return None

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def connect(self, connection, address, port, local=False):
        """ Connect to a remote server and handle the connection(i.e append it).
            Doesn't return. """

        global connecting_to_server
        sock = connection[0]

        # Ugh! Fucking race conditions... *
        # Append this new connection as quickly as possible,
        # so the following if statement
        # will trip correctly on a decent CPU.
        # Moore's law tells me I should come up with a better solution to this problem.
        # But then again, Moore's law is pretty much dead.

        # Make a real copy of the network tuple, not a pointer.
        quasi_network_tuple = tuple(network_tuple)
        self.append(sock, address)  # Append it, quick! (see rant above)

        # Don't connect to an address we're already connected to.
        if connection in quasi_network_tuple:
            not_connecting_msg = str("Not connecting to " + connection[1],
                                     "We're already connected.")
            self.log(not_connecting_msg, "Warning")

            self.remove((sock, address))

        else:
            # Also don't try to connect to multiple servers at once in the same thread.
            if not connecting_to_server:
                connecting_to_server = True

                if not local:

                    self.log(str("Connecting to " + address), in_log_level="Info")
                    sock.connect((address, port))
                    self.log("Successfully connected.", in_log_level="Info")
                    connecting_to_server = False

                elif local:
                    self.remove((sock, address))

                    self.log("Connecting to localhost server...",
                             in_log_level="Info")
                    sock.connect((address, port))

                    self.log("Successfully connected to localhost server",
                             in_log_level="Info")
                    connecting_to_server = False

    def disconnect(self, connection, disallow_local_disconnect=True):
        """ Try to disconnect from a remote server and remove it from the network tuple.
          Returns None if you do something stupid. otherwise don't return """

        try:
            sock = connection[0]
            address_to_disconnect = connection[1]

        except TypeError:
            self.log("Expected a connection tuple, got:", in_log_level="Warning")
            self.log(str('\t') + str(connection), in_log_level="Warning")
            return None

        try:
            # Don't disconnect from localhost. That's done with self.terminate().
            if disallow_local_disconnect:
                if address_to_disconnect == self.get_local_ip() or address_to_disconnect == "127.0.0.1":
                    self.log("Not disconnecting from localhost dimwit.", in_log_level="Warning")

                # Do disconnect from remote nodes. That actually makes sense (when applicable).
                else:
                    verbose_connection_msg = str("Disconnecting from " + address_to_disconnect
                                                 + "\n\t(  " + str(sock) + "  )")
                    self.log(verbose_connection_msg, in_log_level="Info")

                    self.remove(connection)

                    try:
                        sock.close()

                    except (OSError, AttributeError):
                        close_fail_msg = str("Failed to close the socket of "
                                             + address_to_disconnect
                                             + " -> OSError -> disconnect()")
                        self.log(close_fail_msg, in_log_level="Warning")

                    finally:
                        self.log("Successfully disconnected.", in_log_level="Info")

        # Either the socket in question doesn't exist, or the socket is probably [closed].
        except (IndexError, ValueError):
            self.log("Already disconnected from that address, passing...", in_log_level="Warning")
            pass

    """ The following three functions were written by StackOverflow user 
    Adam Rosenfield then modified by me, HexicPyth.
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
        # from the network tuple so it can't cause issues.
        except OSError:
            self.disconnect(connection)

    def broadcast(self, message):
        self.log("Permuting the network tuple", in_log_level="Info")
        self.permute_network_tuple()
        for connection in network_tuple:
            self.send(connection, message, sign=False)  # For each of them send the given message( = Broadcast)

    @staticmethod
    def run_external_command(command):
        # Given a string containing a UNIX command, execute it.
        # Returns 0 -> int (duh)

        os.system(command)
        return 0

    def write_to_page(self, page_id, data, signing=True):
        self.log("Writing to page:" + page_id, in_log_level="Info")
        os.chdir(original_path)

        """ Until we implement Asymmetric crypto, we'll identify ourselves 
        with a hash of our address. That's actually convenient because other
        nodes can reliably tell who (didn't) send a given message """

        if signing:
            our_id = sha3_224(self.get_local_ip().encode()).hexdigest()[:16]
            data_line = str(our_id + ":" + data + "\n")

        else:
            data_line = str(data + "\n")

        file_path = ("../inter/mem/" + page_id + ".bin")

        this_page = open(file_path, "a+")
        this_page.write(data_line)
        this_page.close()

    def respond(self, connection, msg):
        # We received a message, reply with an appropriate response.
        # Doesn't return anything.

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
        global SALT

        full_message = str(msg)
        sig = full_message[:16]
        message = full_message[17:]
        address = connection[1]

        # Fallback in case multiple threads somehow receive the same message at the same time
        sleep(random.uniform(0.008, 0.05))

        # Don't respond to messages we've already responded to.
        if sig in message_list:
            not_responding_to_msg = str("Not responding to " + sig)
            self.log(not_responding_to_msg, in_log_level="Debug")

        # Do respond to messages we have yet to respond to.
        elif sig not in message_list or sig == no_prop:

            # e.x "Client -> Received: echo (ffffffffffffffff) from: 127.0.0.1"
            message_received_log = str('Received: ' + message
                                       + " (" + sig + ")" + " from: " + address)

            self.log(message_received_log, in_log_level="Info")

            if message == "echo":
                """ Simple way to test our connection to a given node."""

                self.log("echoing...", in_log_level="Info")
                self.send(connection, no_prop + ':' + message, sign=False)  # If received, send back

            if message == "stop":
                """ instruct all nodes to disconnect from each other and exit cleanly."""

                # Inform localhost to follow suit.
                localhost_connection = (localhost, "127.0.0.1")
                self.send(localhost_connection, "stop")  # TODO: should we use no_prop here?

                # Do so ourselves
                self.terminate()

            # If we received a foreign address, connect to it. This is address propagation.
            if message.startswith("ConnectTo:"):
                connect_to_address = message[10:]  # len("ConnectTo:") = 10

                # Will return an socket if we're already connected to it.
                connection_status = self.lookup_socket(connect_to_address)
                self.log(str(network_tuple), in_log_level="Debug")

                # If we're not already connected
                if connection_status == 0:

                    # Don't re-connect to localhost. All kinds of bad things happen if you do.
                    if connect_to_address == self.get_local_ip() or connect_to_address == "127.0.0.1":
                        not_connecting_msg = str("Not connecting to " + connect_to_address
                                                 + ";" + " That's localhost :P")

                        self.log(not_connecting_msg, in_log_level="Warning")

                    else:
                        local_address = self.get_local_ip()

                        # Be verbose
                        self.log(str("self.lookup_socket() indicates that "
                                     "we're not connected to " + connect_to_address), in_log_level="Info")

                        self.log(str("self.get_local_ip() indicates that localhost "
                                     "= " + local_address), in_log_level="Info")

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

                                self.log(str("Unable to connect to: " + str(connect_to_address)),
                                         in_log_level="Warning")

                # The address isn't foreign, don't re-connect to it.
                elif connection_status != 0:
                    already_connected_msg = str("Not connecting to " +
                                                connect_to_address +
                                                ";" +
                                                "We're already connected.")
                    self.log(already_connected_msg, "Warning")

            if message.startswith('exec:'):
                # Assuming allow_command_execution is set, execute arbitrary UNIX commands in their own threads.
                if allow_command_execution:
                    command = message[5:]
                    self.log(str("executing: " + command), in_log_level="Info")

                    # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                    # non-isolated fork of a process.
                    command_process = multiprocessing.Process(target=self.run_external_command,
                                                              args=(command,), name='Cmd_Thread')
                    command_process.start()

                # allow_command_execution is not set, don't execute arbitrary UNIX commands from the network.
                else:
                    self.log(("Not executing command: ", message[5:]), in_log_level="Info")

            if message.startswith("newpage:"):
                """ Create a new pagefile that we'll presumably do some 
                parallel or distributed operations with.
                e.x newpage:(64-bit signature)"""

                page_id = message[8:]
                self.log("Creating new page with id: " + str(page_id), in_log_level="Info")

                os.chdir(original_path)
                new_filename = str("../inter/mem/" + page_id + ".bin")
                newpage = open(new_filename, "a+")
                page_list.append(newpage)

            if message.startswith("corecount:"):
                global module_loaded
                import corecount  # If your IDE tells you this module isn't found, it's lying.

                module_loaded = "corecount"
                corecount.respond_start(page_ids, message)

            if message.startswith("fetch:"):
                """ send the contents of page [page_id] to broadcast. We cannot reply directly to
                sender because of message propagation.   . """

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
                self.broadcast(sync_msg)  # We need to broadcast

            if message.startswith("sync:"):
                """ Update our pagefile with information from other node's completed work
                Translation: write to page 
                Syntax: sync:(page id):(data)
                """

                os.chdir(original_path)
                page_id = message[5:][:16]
                data = message[22:]

                self.log("Syncing " + data + " into page:" + page_id, in_log_level="Info")

                file_path = "../inter/mem/" + page_id + ".bin"

                file_exists = False

                try:
                    existing_pagelines = open(file_path, "r+").readlines()
                    file_exists = True

                except FileNotFoundError:
                    self.log("Cannot open a non-existent page")

                if file_exists:
                    duplicate = False
                    local = False

                    # How do we sort out duplicates?
                    for line in existing_pagelines:
                        if line == data:
                            duplicate = True
                            self.log("Not writing duplicate data into page " + page_id)
                            break

                    if not duplicate:
                        data_id = data[:16]
                        local_id = sha3_224(self.get_local_ip().encode()).hexdigest()[:16]
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
                    # The following two lines of SLOC are the work of "Marcel" from StackOverflow

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
                    self.log("\n\t" + str(len(newlines)) + " Node(s) have contributed to the network.\n"
                                                           "The network tuple(+1) is of"
                                                           " length " + str(len(network_tuple) + 1),
                             in_log_level="Debug")

                    if len(newlines) == len(network_tuple)+1:
                        # Do module-specific I/O
                        if module_loaded == "corecount":
                            os.chdir(original_path)
                            import corecount
                            corecount.start(page_id, raw_lines, newlines)
                            module_loaded = ""

            if message.startswith("file:"):
                # file:(64-bit file hash):(32-bit file length):(128-bit origin address identifier)
                self.log("Not doing anything with file request because they are not implemented yet.")
                message_to_parse = message[5:]  # Remove "file:" from message string so we can parse it correctly.
                file_hash = message_to_parse[:16]
                file_length = message_to_parse[17:][:8]
                origin_addr_id = message_to_parse[26:]
                self.log("Our Address Identifier: "+ADDR_ID, in_log_level="Debug")
                self.log("Received message destined for Address Identifier: "+origin_addr_id, in_log_level="Debug")

            # Remove the specified node from the network (i.e disconnect from it)

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
                self.log("Voting a proxy", in_log_level="Info")

                vote_msg = "vote:"+election_reason
                self.broadcast(self.prepare(vote_msg))

                proxy = Primitives.find_representative(election_list, election_reason)  # Doesn't work (race condition)

                # Will be continued in self.init_file(stage=1), called during the elect: flag

            if message.startswith("remove:"):

                address_to_remove = message[7:]

                try:

                    # Don't disconnect from localhost. That's what self.terminate is for.
                    if address_to_remove != self.get_local_ip() and address_to_remove != "127.0.0.1":

                        sock = self.lookup_socket(address_to_remove)

                        if sock:
                            self.log("Remove -> Disconnecting from " + address_to_remove,
                                     in_log_level="Info")

                            # lookup the socket of the address we want to remove
                            connection_to_remove = (sock, address_to_remove)
                            self.log(str("Who's connection is: " + str(connection_to_remove)),
                                     in_log_level="Info")
                            self.disconnect(connection_to_remove)

                        else:
                            self.log("Not disconnecting from a non-existent connection",
                                     in_log_level="Warning")

                    else:
                        self.log("Not disconnecting from localhost, dimwit.", in_log_level="Warning")

                except (ValueError, TypeError):
                    # Either the address we're looking for doesn't exist, or we're not connected it it.
                    self.log(str("Sorry, we're not connected to " + address_to_remove),
                             in_log_level="Warning")
                    pass

            # Append signature(hash) to the message list, or in the case of sig=no_prop, do nothing.
            if sig != no_prop:
                message_list.append(sig)

                # End of respond()
                # Propagate the message to the rest of the network.
                self.log(str('Broadcasting: ' + full_message), in_log_level="Debug")
                self.broadcast(full_message)

            if message.startswith("vote:"):
                self.log("Ongoing election: "+str(ongoing_election), in_log_level="Debug")

                if not ongoing_election:
                    ongoing_election = True
                    reason = message[5:]
                    print(reason)
                    election_tuple = (reason, "TBD")
                    election_list.append(election_tuple)

                    campaign_int = random.randint(1, 2**128)
                    our_campaign = campaign_int

                    self.log("Campaigning for "+str(campaign_int), in_log_level="Info")
                    campaign_msg = self.prepare("campaign:"+reason+":"+str(campaign_int))
                    self.broadcast(campaign_msg)

            if message.startswith("campaign:"):
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

                        election_log_msg = str(winning_int) + " Won the election for: " + winning_reason
                        self.log(election_log_msg, in_log_level="Info")

                        if our_campaign == int(winning_int):
                            self.log("We won the election for: "+winning_reason, in_log_level="Info")
                            elect_msg = self.prepare("elect:"+winning_reason+":"+str(self.get_local_ip()))
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
                Injector = inject.NetworkInjector()
                args = Injector.parse_cmd(message)
                reason = args[0]
                new_leader = args[1]
                index = Primitives.find_election_index(election_list, reason)
                election_list = Primitives.set_leader(election_list, index, new_leader)
                ongoing_election = False

                if reason.startswith('dfs'):
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
                print(election_list)
                print("\n")

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
                    self.log(conn_severed_msg, in_log_level="Warning")

                    self.disconnect(conn)
                    listener_terminated = True

                if incoming == 1:
                    self.disconnect(conn)
                    conn_not_existent_msg = str("Connection to " + str(in_sock) +
                                                "doesn't exist, terminating listener_thread()")
                    self.log(conn_not_existent_msg, in_log_level="Warning")
                    listener_terminated = True

        # Start listener in a new thread
        threading.Thread(target=listener_thread, args=(connection,), name='listener_thread').start()

    def terminate(self):
        # Disconnect from the network and exit the client cleanly.
        # Returns 0 -> int (duh)

        global terminated
        global network_tuple
        global page_list

        self.log("Safely terminating our connections...", in_log_level="Warning")

        index = 0
        for file in page_list:
            self.log("Closing pages..", in_log_level="Info")
            file.close()
            try:
                os.remove(file.name)
            except FileNotFoundError:
                self.log("Not removing non-existent page")
            self.log(str("Terminating connection to "), in_log_level="Info")

        for connection in network_tuple:
            address = connection[1]
            self.log(str("Terminating connection to " + address), in_log_level="Info")
            self.disconnect(connection, disallow_local_disconnect=False)
            index += 1

        self.log("Quietly Dying...")
        terminated = True
        return 0

    def initialize(self, port=3705, network_architecture="Complete",
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

        # Global variable assignment
        PORT = port
        allow_command_execution = command_execution
        allow_file_storage = file_storage
        log_level = default_log_level

        Primitives = primitives.Primitives(log_level, sub_node)
        SALT = secrets.token_hex(16)
        ADDR_ID = Primitives.gen_addr_id(SALT)

        for item in modules:
            import_str = "import " + item
            loaded_modules.append(item)
            exec(import_str)

        # Stage 0
        self.log("Initializing...", in_log_level="Info")
        localhost_connection = (localhost, '127.0.0.1')

        try:
            self.connect(localhost_connection, 'localhost', port, local=True)

            self.log("Connection to localhost successful", in_log_level="Info")
            self.log("Starting listener on localhost...", in_log_level="Info")

            self.listen(localhost_connection)

        except ConnectionRefusedError:

            self.log("Connection to localhost was not successful; check that your server is "
                     "initialized, and try again later.", in_log_level="Warning")
            quit(1)

        except FileNotFoundError:
            pass

        self.log("Attempting to connect to remote server... (Initiating stage 1)",
                 in_log_level="Info")

        # Stage 1
        if network_architecture == "Complete":

            if remote_addresses:

                for remote_address in remote_addresses:
                    sock = socket.socket()

                    try:
                        connection = (sock, remote_address)
                        self.connect(connection, remote_address, port)

                        self.log(str("Starting listener on " + remote_address), in_log_level="Info")
                        self.listen(connection)

                        self.send(connection, no_prop+":echo", sign=False)

                    except ConnectionRefusedError:
                        self.log("Unable to connect to remove server; Failed to bootstrap.",
                                 in_log_level="Warning")
            else:
                self.log("Initializing with no remote connections...", in_log_level="Info")
