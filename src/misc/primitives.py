import struct
import socket
import datetime
from hashlib import sha3_224


class Primitives:

    def __init__(self, sub_node, global_log_level):
        self.LOG_LEVEL = global_log_level
        self.SUB_NODE = sub_node

    def log(self, log_message, in_log_level='Warning'):
        # TODO: Modularize this function

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

    # We would have send() here, but send() references disconnect(), which references remove(), which
    # relies on the network tuple to function. Implementing remove() here would be impractical.

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
                print("Message length: "+str(msg_length))  # DEBUG
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

        data = ''

        while len(data) < n:
            try:
                packet = (sock.recv(n - len(data)))
                packet = packet.decode()  # If this fails, we still have a packet to work with/debug

            except OSError:
                self.log("Connection probably down or terminated (OSError: receiveall()",
                         in_log_level="Warning")
                raise ValueError

            # Something corrupted in transit. Let's just ignore the bad pieces for now.
            except UnicodeDecodeError:
                raw_packet = (sock.recv(n - len(data)))
                packet = raw_packet.decode('utf-8', 'ignore')
                print("\nWarning: Packet failed to decode:", raw_packet)  # TODO: Why do we receive b'ffff'?
                print("\tReturning: ", packet)

            except MemoryError:
                print("\nERROR: MemoryError occurred decoding a packet. Returning an empty string\n")
                print("\tn: "+str(n))  # DEBUG
                packet = ""

            if not packet:
                return None

            else:
                data += packet
        return data.encode('utf-8', 'ignore')

    def find_representative(self, election_list, reason):
        for index, tup in enumerate(election_list):
            if tup[0] == reason:
                return tup[1]
        else:
            return -1

    def find_election_index(self, election_list, reason):
        for index, tup in enumerate(election_list):
            if tup[0] == reason:
                return index
        else:
            return -1

    def set_leader(self, election_list, index, leader):
        print(election_list)
        election_tuple = election_list[index]

        derived_list = list(election_tuple)
        derived_list[1] = leader

        election_list.pop(index)
        new_tuple = tuple(derived_list)
        election_list.insert(index, new_tuple)
        return election_list

    def set_file_proxy(self, checksum, in_list, proxy_addr):
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

    def find_file_tuple(self, in_list, checksum):
        # File list: (size, path, checksum, proxy)
        file_tuple = ()
        for f_tuple in in_list:
            if list(f_tuple)[2] == checksum:
                file_tuple = f_tuple
                return file_tuple
        return -1

