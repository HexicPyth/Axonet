import struct
import socket
import datetime
import sys
from hashlib import sha3_224


class Primitives:

    def __init__(self, sub_node, global_log_level):
        self.LOG_LEVEL = global_log_level
        self.SUB_NODE = sub_node

    def log(self, log_message, in_log_level='Warning'):

        """ Process and deliver program output in an organized and
        easy to read fashion. Never returns. """

        # input verification
        levels = ["Debug", "Info", "Warning"]

        allowable_levels = []
        allow_further_levels = False  # Allow all levels after the input.

        for level in levels:
            if allow_further_levels:
                allowable_levels.append(level)

            if level == self.LOG_LEVEL:
                allowable_levels.append(level)
                allow_further_levels = True

        if in_log_level not in levels or in_log_level not in allowable_levels:
            pass
            print(in_log_level)
            print(levels)
            print(allowable_levels)

        else:
            print(self.SUB_NODE, "->", in_log_level + ":", log_message)

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
            self.log("Failed to identify local IP address; No network connection detected", in_log_level="Warning")

            local_ip = "127.0.0.1"

        finally:
            temp_socket.close()

        return local_ip

    def gen_addr_id(self, addr_salt):
        local_addr = self.get_local_ip()
        data_to_hash = local_addr + addr_salt
        addr_id = sha3_224(data_to_hash.encode()).hexdigest()[:32]
        return addr_id

    @staticmethod
    def prepare(message):
        """ Assign unique hashes to messages ready for transport.
            Returns (new hashed message) -> str
            Note: These timestamps may be vulnerable to replay attacks.
            Some day we should start using random data instead. """

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

    def receive(self, connection):
        """ Read message length and unpack it into an integer
        Returns None if self.receiveall fails, or nothing at all otherwise.
        """

        sock = connection[0]
        try:
            raw_msg_length = self.receiveall(sock, 4)
            if not raw_msg_length:
                return None

            try:
                msg_length = struct.unpack('>I', raw_msg_length)[0]

            # This packet was corrupted, just return an empty string.
            except TypeError:
                return ""

            try:
                return self.receiveall(sock, msg_length).decode('utf-8', 'ignore')

            except AttributeError:
                return 1

        # This socket disconnected. Return 1 so the calling function(probably the listener) knows what happened.
        except ValueError:
            return 1

    def receiveall(self, sock, n):
        """ Helper function to receive n bytes.
            Returns None(-> NoneType) if/when EOF is hit.
        """

        data = b''

        while len(data) < n:
            try:
                raw_packet = (sock.recv(n - len(data)))
                packet = raw_packet.decode()  # If this fails, we still have a packet to work with/debug

            except OSError:
                self.log("Connection probably down or terminated (OSError: receiveall()",
                         in_log_level="Warning")
                raise ValueError

            # Something corrupted in transit. Let's just ignore the bad pieces for now.
            except UnicodeDecodeError:

                if len(raw_packet) == 4:  # raw_packet should not be referenced before assignment. TODO: will it be?

                    # The first four bytes of a message are it's binary length(see self.send); it'll almost never
                    # decode anyway; ignore it. (Fix issue #22)
                    packet = raw_packet

                else:

                    packet = raw_packet.decode('utf-8', 'ignore')
                    print("\nWarning: Packet failed to decode:", raw_packet)  # TODO: Why do we receive b'ffff'?
                    print("\tReturning: ", packet)

            except MemoryError:

                print("\nERROR: MemoryError occurred decoding a packet. Returning an empty string\n")
                packet = ""

            if not packet:
                return None

            else:
                try:
                    data += bytes(packet, 'ascii')

                # We're appending bytes
                except TypeError:
                    data += packet
        return data

    @staticmethod
    def find_representative(election_list, reason):
        for index, tup in enumerate(election_list):
            if tup[0] == reason:
                return tup[1]
        else:
            return -1

    @staticmethod
    def find_election_index(election_list, reason):
        for index, tup in enumerate(election_list):
            if tup[0] == reason:
                return index
        else:
            return -1

    @staticmethod
    def set_leader(election_list, index, leader):
        print(election_list)
        election_tuple = election_list[index]

        derived_list = list(election_tuple)
        derived_list[1] = leader

        election_list.pop(index)
        new_tuple = tuple(derived_list)
        election_list.insert(index, new_tuple)
        return election_list

    @staticmethod
    def set_file_proxy(checksum, in_list, proxy_addr):
        # File list: (size, path, checksum, proxy)
        file_tuple = ()
        for f_tuple in in_list:
            if list(f_tuple)[2] == checksum:
                file_tuple = f_tuple
                break

        derived_list = list(file_tuple)
        derived_list[3] = proxy_addr
        new_file_tuple = tuple(derived_list)
        return new_file_tuple

    @staticmethod
    def find_file_tuple(in_list, checksum):
        # File list: (size, path, checksum, proxy)
        file_tuple = ()
        for f_tuple in in_list:
            if list(f_tuple)[2] == checksum:
                file_tuple = f_tuple
                return file_tuple
        return -1

    @staticmethod
    def parse_cmd(in_cmd):
        """Parse an input command for arguments and return them in a List"""
        args = []

        # Find the command substring and remove it from the input
        cmd_index = in_cmd.find(":")
        in_cmd = in_cmd[cmd_index + 1:]

        number_of_args = in_cmd.count(":") + 1

        # All arguments are separated by colons.
        # Find colon index -> Read until next colon -> append argument to list -> remove argument -> repeat.

        for i in range(0, number_of_args):
            argument_index = in_cmd.find(":")

            if argument_index != -1:

                argument = in_cmd[:argument_index]
                args.append(argument)

                in_cmd = in_cmd[argument_index + 1:]

            else:
                args.append(in_cmd)
        return args

