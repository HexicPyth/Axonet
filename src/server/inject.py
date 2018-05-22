import multiprocessing
import struct
import os
import server
import codecs
current_message = None


class NetworkInjector(multiprocessing.Process):

    # Send a given message to a specific node
    # Slightly modified compared to the server's send method
    def send(self, connection, msg, signing=True):
        sock = connection[0]
        address = connection[1]
        global current_message
        if signing:
            msg = server.Server.prepare(msg).encode('utf-8')

        else:
            msg.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg

        if not current_message:
            current_message = msg
        try:
            print("Server -> Injector -> Broadcast: " + current_message.decode() + " to the network.")

        except UnicodeDecodeError:
            print("Server -> Injector -> Broadcast (unable to decode) to the network")

        finally:
            try:
                sock.sendall(current_message)

            # Something's up with the node we're interacting with.
            # Notify the server with a return code.
            except BrokenPipeError:
                return address

            except OSError:
                print("Injector -> Something went wrong with "+address)

    def broadcast(self, message, network_tuple):
        global current_message
        return_code = 0
        for connection in network_tuple:
            address = connection[1]
            print("Sending: "+"'"+message+"'"+" to "+address)  # print("Sending: '(message)' to (address)")
            try:
                send_status = self.send(connection, message, network_tuple)  # For each of them send the given message

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
        formatted_flags = []
        this_dir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(this_dir)

        # Switch to the interaction directory.
        os.chdir("../inter/")

        # Parse all files in the interaction directory for flags to broadcast.
        for file in os.listdir('./'):
            do_continue = True

            try:
                file_to_read = open(file, 'r+')
            except IsADirectoryError:
                do_continue = False
            finally:
                if do_continue:
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

        return formatted_flags

    def interpret(self, in_msg, net_tuple):
        msg_type = ""
        if in_msg[:1] == "$":
            msg_type = "command"
        else:
            msg_type = "flag"

        if msg_type == "flag":
            return self.broadcast(in_msg, net_tuple)

        elif msg_type == "command":
            in_cmd = in_msg[1:]

            # TODO: Implement our algorithms here.
            print("Received command: "+in_cmd)

            if in_cmd == "corecount":
                print("Injector -> info: Initiating a core count")
                id_length = 16

                # Get a random 64-bit id for this operation
                op_id = codecs.encode(os.urandom(int(id_length / 2)), 'hex').decode()

                self.broadcast("newpage:"+op_id, net_tuple)
                self.broadcast("corecount:"+op_id, net_tuple)
            return 0

    def init(self, network_tuple, msg=None):
        msg = str(input("Please enter flag to inject into network:  "))

        print("Server/Injector -> Broadcasting the contents of the "
              "interaction directory", "to the network")

        for flag in self.read_interaction_directory():
            self.interpret(flag, network_tuple)

        print("Server/Injector -> Broadcasting", msg, "to the network")
        return self.interpret(msg, network_tuple)
