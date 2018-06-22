import multiprocessing
import struct
import os
import server
from hashlib import sha3_224
import datetime
import sys
original_path = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, '../inter/modules/')

current_message = None


class NetworkInjector(multiprocessing.Process):

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

    # Send a given message to a specific node
    # Slightly modified compared to the server's send method

    @staticmethod
    def send(connection, msg, sign=True):
        sock = connection[0]
        address = connection[1]
        global current_message
        if sign:
            msg = server.Server.prepare(msg).encode('utf-8', 'ignore')

        elif not sign:
            msg = msg.encode()

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg

        if not current_message:  # True when current_message=None
            current_message = msg
        try:
            print("Server -> Injector -> Send: " + current_message.decode() + " to the network.")

        except UnicodeDecodeError:
            print("Server -> Injector -> Send: (unable to decode) to the network")

        finally:
            try:
                sock.sendall(current_message)
                current_message = None

            # Something's up with the node we're interacting with.
            # Notify the server with a return code.
            except BrokenPipeError:
                return address

            except OSError:
                print("Injector -> Something went wrong with "+address)

    @staticmethod
    def lookup_socket(address, network_tuple):
        # Do a brute force search for a specific socket.
        # Maybe this can be optimized by caching the indexes of commonly-used connections?

        for item in network_tuple:
            discovered_address = item[1]
            if address == discovered_address:
                return item[0]

    @staticmethod
    def lookup_address(in_sock, network_tuple):
        # Do a brute force search for a specific address.
        # Maybe this can be optimized by caching the indexes of commonly-used connections?
        for item in network_tuple:
            discovered_socket = item[0]
            if in_sock == discovered_socket:
                return item[1]

    def broadcast(self, message, network_tuple, signing=True):
        global current_message
        return_code = 0

        if signing:
            # Make sure we use the same signature for each node we send to.
            message_to_send = self.prepare(message)

        else:
            message_to_send = message

        for connection in network_tuple:
            address = connection[1]
            print("Sending: "+"'"+message+"'"+" to "+address)  # print("Sending: '(message)' to (address)")
            try:
                send_status = self.send(connection, message_to_send, sign=signing)

            except OSError:  # Probably Bad file descriptor
                print("Server/Injector -> Warning: errors occurred sending to: "+str(connection))
                send_status = None

            # The server doesn't interact directly with NetworkInjector.send();
            # If it fails, pass it's return code to the server.
            if type(send_status) == str:
                return_code = send_status

        current_message = None  # TODO: clarify the purpose of this variable. What does it do?
        return return_code

    def kill(self):
        print("Injector -> kill() : Reluctantly terminating myself... * cries to the thought of SIGKILL *")

    @staticmethod
    def read_interaction_directory():
        # Read flags from lines in files in src/inter/ and broadcast them
        # TODO: this should be run in a seperate thread as part of the server. As of now, this won't run without
        # ...some form of user input. User input should never be necessary in (potentially) headless clusters.

        global original_path

        formatted_flags = []
        os.chdir(original_path)

        # Switch to the interaction directory.
        os.chdir("../inter/")

        # Parse all files in the interaction directory for flags to broadcast.
        for file in os.listdir('./'):
            do_continue = True
            file_to_read = None

            try:
                file_to_read = open(file, 'r+')

            except IsADirectoryError:
                do_continue = False

            finally:
                if do_continue and file_to_read:
                    flags = file_to_read.readlines()

                    # the flags we get from a file with (naturally) contain newlines. Let's remove them.
                    for raw_flag in flags:
                        print(raw_flag)
                        formatted_flag = raw_flag.split('\n')[0]
                        formatted_flags.append(formatted_flag)
                        flags.remove(raw_flag)

                    file_to_read.seek(0)
                    file_to_read.write(''.join(flags))
                    file_to_read.truncate()
                    file_to_read.close()

        os.chdir(original_path)
        return formatted_flags

    def interpret(self, in_msg, net_tuple):
        if in_msg[:1] == "$":
            msg_type = "command"
        else:
            msg_type = "flag"

        if msg_type == "flag":
            return self.broadcast(in_msg, net_tuple)

        elif msg_type == "command":
            in_cmd = in_msg[1:]

            if in_cmd == "corecount":
                os.chdir(original_path)

                import corecount
                corecount.initiate(in_cmd, net_tuple)

            return 0

    def init(self, network_tuple, loaded_modules, msg=None):
        for item in loaded_modules:
            import_str = "import "+item
            exec(import_str)

        msg = str(input("Please enter flag to inject into network:  "))

        print("Server/Injector -> Broadcasting the contents of the "
              "interaction directory", "to the network")

        for flag in self.read_interaction_directory():
            self.interpret(flag, network_tuple)

        print("Server/Injector -> Broadcasting", msg, "to the network")
        return self.interpret(msg, network_tuple)
