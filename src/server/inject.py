import multiprocessing
import struct
from server import Server
current_message = None


class NetworkInjector(multiprocessing.Process):

    # Send a given message to a specific node
    # Slightly modified compared to the server's send method
    def send(self, connection, msg, signing=True):
        sock = connection[0]
        address = connection[1]
        global current_message
        if signing:
            msg = Server.prepare(msg).encode('utf-8')

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
        self.terminate()
        return

    def init(self, network_tuple):
        msg = str(input("Please enter flag to inject into network:  "))

        print("Server/Injector -> Broadcasting", msg, "to the network")
        return self.broadcast(msg, network_tuple)
