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
localhost.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Nobody likes TIME_WAIT-ing. Add SO_REUSEADDR.

PORT = 3705
network_tuple = ()  # (socket, address)
ballet_tuple = ([], [])  # (value, address)
message_list = []
page_list = []  # temporary file objects to close
page_ids = []

cluster_rep = None  # type -> bool
ongoing_election = False
no_prop = "ffffffffffffffff"  # True:[message] = No message propagation.
terminated = False  # If true: the client has been instructed to terminate; inform our functions and exit cleanly.


# To be set by init()
allow_command_execution = False  # Don't execute arbitrary UNIX commands when casually asked, that's bad :]
connecting_to_server = False
allow_file_storage = True
log_level = ""  # "Debug", "Info", or "Warning"; To be set by init


class Client:

    @staticmethod
    def log(log_message, in_log_level='Warning', sub_node="Client"):

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
            print(sub_node, "->", in_log_level + ":", log_message)

    def get_local_ip(self):
        # Creates a temporary socket and connects to subnet, yielding our local address.
        # Returns: (local ip address) -> str
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

        return 0  # Socket not found

    @staticmethod
    def lookup_address(in_sock):  # TODO: optimize me
        for item in network_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

        return 0  # Address not found

    @staticmethod
    def permute_network_tuple():
        # Permute the network tuple in place
        # Returns nothing (network_tuple is a global variable)
        cs_prng = random.SystemRandom()
        global network_tuple

        network_list = list(network_tuple)
        cs_prng.shuffle(network_list)
        new_network_tuple = tuple(network_list)
        network_tuple = new_network_tuple

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

    # Remove a connection from the network_tuple
    def remove(self, connection):
        global network_tuple

        # Tuples are immutable; convert it to a list.
        network_list = list(network_tuple)

        # Identify and remove said connection
        try:
            index = network_list.index(connection)
            network_list.pop(index)

        # Connection not in network tuple, or socket is [closed]
        except ValueError:
            self.log(str("Not removing non-existent connection: "+str(connection)),
                     in_log_level="Warning")
            return None

        # (Again) tuples are immutable; replace the old one with the new one
        network_tuple = tuple(network_list)

    def connect(self, connection, address, port, local=False):
        # Connect to a remote server and handle the connection(i.e append it).
        # Returns nothing.
        global connecting_to_server
        sock = connection[0]

        # * Ugh! Fucking race conditions... *
        # Append this as quickly as possible, so the following if statement
        # will trip correctly on a decent CPU.

        quasi_network_tuple = tuple(network_tuple)  # Make a copy of the network tuple to reference
        self.append(sock, address)

        if connection in quasi_network_tuple:
            not_connecting_msg = str("Not connecting to "+connection[1],
                                     "We're already connected.")
            self.log(not_connecting_msg, "Warning")

            self.remove((sock, address))

        else:
            if not connecting_to_server:
                connecting_to_server = True

                if not local:

                    self.log(str("Connecting to "+address), in_log_level="Info")
                    sock.connect((address, port))
                    self.log("Successfully connected.", in_log_level="Info")
                    connecting_to_server = False

                elif local:
                    self.remove((sock, address))

                    self.log("Connecting to localhost server...", in_log_level="Info")
                    sock.connect((address, port))
                    self.log("Successfully connected to localhost server", in_log_level="Info")
                    connecting_to_server = False

    def disconnect(self, connection, disallow_local_disconnect=True):
        # Try to disconnect from a remote server and remove it from the network tuple.
        # Returns None if you try to do something stupid. otherwise returns nothing at all.

        try:
            sock = connection[0]
            address_to_disconnect = connection[1]

        except TypeError:
            self.log("Expected a connection tuple, got:", in_log_level="Warning")
            self.log(str('\t')+str(connection), in_log_level="Warning")
            return None

        try:
            # Don't disconnect from localhost. That's done with self.terminate().
            if disallow_local_disconnect:
                if address_to_disconnect == self.get_local_ip() or address_to_disconnect == "127.0.0.1":
                    self.log("Not disconnecting from localhost dimwit.", in_log_level="Warning")

                # Do disconnect from remote nodes. That actually makes sense.
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

    ''' The following three functions were written by StackOverflow user 
    Adam Rosenfield and modified by me, HexicPyth.
    https://stackoverflow.com/a/17668009
    https://stackoverflow.com/users/9530/adam-rosenfield '''

    def send(self, connection, message, sign=True):
        # Helper function to encode a given message and send it to a given server.
        # Returns nothing.
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

    def receiveall(self, sock, n):
        # Helper function to receive n bytes.
        # returns None if EOF is hit

        data = ''

        while len(data) < n:
            try:
                packet = (sock.recv(n - len(data))).decode()

            except OSError:
                self.log("Connection probably down or terminated (OSError: receiveall()",
                         in_log_level="Warning")
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
            return 1

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
        print("!!!!")
        this_dir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(this_dir)

        # Until we implement Asymmetric crypto, we'll identify ourselves with a hash of our address.
        if signing:
            our_id = sha3_224(self.get_local_ip().encode()).hexdigest()[:16]
            data_line = str(our_id + ":" + data + "\n")

        else:
            our_id = ""  # Hack our string operations to write nothing in the id field.
            data_line = str(data + "\n")

        file_path = ("../inter/mem/"+page_id+".bin")
        this_page = open(file_path, "a+")
        this_page.write(data_line)
        this_page.close()

    def respond(self, connection, msg):
        # We received a message, reply with an appropriate response.
        # Doesn't return anything.

        global message_list
        global ongoing_election
        global ballet_tuple
        global cluster_rep
        global page_list
        global page_ids

        full_message = str(msg)
        sig = full_message[:16]
        message = full_message[17:]
        address = connection[1]

        # Don't respond to messages we've already responded to.
        if sig in message_list:
            not_responding_to_msg = str("Not responding to "+sig)
            self.log(not_responding_to_msg, in_log_level="Debug")

        # Do respond to messages we have yet to respond to.
        elif sig not in message_list or sig == no_prop:

            # Find the address of the socket we're receiving from...

            # e.x "Client -> Received: echo (ffffffffffffffff) from: 127.0.0.1"
            message_received_log = str('Received: ' + message
                                       + " (" + sig + ")" + " from: " + address)

            self.log(message_received_log, in_log_level="Info")

            # Simple connection test mechanism.
            if message == "echo":
                self.log("echoing...", in_log_level="Info")
                self.send(connection, no_prop + ':' + message, sign=False)  # If received, send back

            # Easy way to instruct all nodes to disconnect from each other and exit cleanly.
            if message == "stop":
                # Inform our server to exit cleanly
                localhost_connection = (localhost, "127.0.0.1")
                self.send(localhost_connection, "stop")

                # Do so ourselves
                self.terminate()

            # If we received a foreign address, connect to it. This is address propagation.
            if message.startswith("ConnectTo:"):
                connect_to_address = message[10:]  # len("ConnectTo:") = 10

                # The address is foreign, connect to it.

                # Will return None if no socket is found(i.e we're not connected)
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
                        self.log(str("self.lookup_socket() indicates that "
                                 "we're not connected to "+connect_to_address), in_log_level="Info")

                        self.log(str("self.get_local_ip() indicates that localhost "
                                     "= " + local_address), in_log_level="Info")

                        new_socket = socket.socket()

                        new_connection = (new_socket, connect_to_address)

                        # If we're not connected to said node
                        if not connection_status:
                            try:
                                self.connect(new_connection, connect_to_address, PORT)
                                self.listen(new_connection)

                            # probably bad file descriptor in self.connect()
                            except OSError:
                                self.log(str("Unable to connect to: "+str(connect_to_address)),
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
                    self.log(str("executing: "+command), in_log_level="Info")

                    # Warning: This is about to execute some arbitrary UNIX command in it's own nice little
                    # non-isolated fork of a process.
                    command_process = multiprocessing.Process(target=self.run_external_command,
                                                              args=(command,), name='Cmd_Thread')
                    command_process.start()

                # allow_command_execution is not set, don't execute arbitrary UNIX commands from the network.
                else:
                    self.log(("Not executing command: ", message[5:]), in_log_level="Info")

            if message.startswith("newpage:"):

                # e.x newpage:(64-bit signature):

                page_id = message[8:]
                self.log("Creating new page with id: "+str(page_id), in_log_level="Info")

                # create a new file to store our page fragments in.

                this_dir = os.path.dirname(os.path.realpath(__file__))
                os.chdir(this_dir)

                new_filename = str("../inter/mem/"+page_id+".bin")
                newpage = open(new_filename, "a+")
                page_list.append(newpage)

            if message.startswith("corecount:"):
                page_id = message[10:]
                if page_id not in page_ids:
                    num_of_cores = str(multiprocessing.cpu_count())
                    self.write_to_page(page_id, num_of_cores)
                elif page_id in page_ids:
                    pass

            if message.startswith("fetch:"):
                ''' send the contents of page [page_id] to broadcast. We cannot reply directly to
                sender because of message propagation.   . '''

                page_ident = message[6:]

                # Read contents of page
                this_dir = os.path.dirname(os.path.realpath(__file__))
                os.chdir(this_dir)
                pagefile = open("../inter/mem/"+page_ident+".bin", "r+")

                page_contents = ''.join(pagefile.readlines())
                sync_msg = (no_prop+":"+"sync:"+page_ident+":"+page_contents)

                self.broadcast(sync_msg)  # We need to broadcast

            if message.startswith("sync:"):
                this_dir = os.path.dirname(os.path.realpath(__file__))
                os.chdir(this_dir)

                page_id = message[5:][:16]
                data = message[22:]
                print(page_id)
                print(data)
                file_path = "../inter/mem/"+page_id+".bin"
                existing_pagelines = open(file_path, "r+").readlines()
                print(existing_pagelines)

                duplicate = False
                local = False

                # How do we sort out duplicates?
                for line in existing_pagelines:
                    if line == data:
                        duplicate = True
                        print("Not writing duplicate data into "+page_id)
                        break
                    else:
                        pass

                if not duplicate:
                    data_id = data[:16]
                    local_id = sha3_224(self.get_local_ip().encode()).hexdigest()[:16]
                    if data_id == local_id:
                        # Don't re-write data about ourselves. We already did that with 'corecount'.
                        print("Not being hypocritical in page "+page_id)
                        local = True

                    if not local:
                        print("Writing "+data + "to page " + page_id)
                        self.write_to_page(page_id, data, signing=False)


                # Thank you Marcell from StackOverflow for the following.
                uniqlines = set(open(file_path).readlines())
                uniq_file = open(file_path, 'w').writelines(set(uniqlines))

            if message.startswith("file:"):
                # Eventually we'll be able to distribute shared
                # retrievable information, like public keys, across the network.
                if allow_file_storage:
                    info = message[5:]
                    file_hash = info[:16]
                    verbose_info_dump = str("Info = " + info +
                                            '\n File hash = ' + file_hash)
                    self.log(verbose_info_dump, in_log_level="Info")

                    # file_length = info[16:20]  Let's put this aside for now
                    origin_address = info[22::]
                    new_message = str(no_prop+":affirm"+":"+file_hash+":"+origin_address)
                    self.log(str("Affirming request for file: "+file_hash), in_log_level="Info")

                    print(origin_address)

                    origin_socket = self.lookup_socket(origin_address)
                    print(origin_socket)
                    if origin_socket == 0:
                        self.log("Apparently we are not connected to the origin of that request,"
                                 " passing;", in_log_level="Info")
                    else:
                        origin_connection = (origin_socket, origin_address)
                        self.send(origin_connection, new_message, sign=False)

                else:
                    self.log("As per arguments to self.init(),"
                             " not responding to requests for file storage", in_log_level="Info")

            # Remove the specified node from the network (i.e disconnect from it)
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
                            self.log(str("Who's connection is: "+str(connection_to_remove)),
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

    def listen(self, connection):
        # Listen for incoming messages and call self.respond() to respond to them.
        # Also, deal with disconnections as they are most likely to throw errors here.
        # Returns nothing.

        def listener_thread(conn):
            in_sock = conn[0]
            global terminated
            listener_terminated = False  # When set, this specific instance of listener_thread is stopped.

            while not listener_terminated and not terminated:
                incoming = self.receive(conn)
                raw_message = incoming
                try:
                    if incoming:
                        self.respond(conn, raw_message)

                except TypeError:
                    conn_severed_msg = str("Connection to "+str(in_sock)
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
            os.remove(file.name)

        for connection in network_tuple:
            address = connection[1]
            self.log(str("Terminating connection to " + address), in_log_level="Info")
            self.disconnect(connection, disallow_local_disconnect=False)
            index += 1

        terminated = True
        print("!!!!!")

        return 0

    def initialize(self, port=3705, network_architecture="Complete",
                   remote_addresses=None, command_execution=False,
                   file_storage=True, default_log_level="Debug"):

        # Initialize the client, set any global variable that need to be set, etc.

        global allow_command_execution
        global allow_file_storage
        global localhost
        global log_level
        global PORT

        PORT = port  # Global variable assignment
        allow_command_execution = command_execution
        allow_file_storage = file_storage
        log_level = default_log_level

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

                        self.send(connection, "echo")

                    except ConnectionRefusedError:
                        self.log("Unable to connect to remove server; Failed to bootstrap.",
                                 in_log_level="Warning")
            else:
                self.log("Initializing with no remote connections...", in_log_level="Info")
