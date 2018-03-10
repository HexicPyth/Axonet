import multiprocessing
import struct
import datetime
from hashlib import sha3_224
current_message = None


class NetworkInjector(multiprocessing.Process):

    @staticmethod
    def prepare(message):  # Process our message for broadcasting (please ignore the mess :])
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

    def send(self, connection, msg, network_tuple, signing=True):
        sock = connection[0]
        address = connection[1]
        global current_message
        if signing:
            msg = self.prepare(msg).encode('utf-8')

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
                y = self.send(connection, message, network_tuple)  # For each of them send the given message

            except OSError:  # Probably Bad file descriptor
                print("Server/Injector -> Warning: errors occurred sending to: "+str(connection))
                y = None
                
            if type(y) == str:
                return_code = y

        current_message = None  # reset current message
        return return_code

    def kill(self):
        print("Injector -> Terminate() : Reluctantly terminating myself... * cries to the thought of SIGKILL *")
        self.terminate()
        return

    def init(self, network_tuple):

        msg = str(input("Please enter flag to inject into network:  "))
        print("Server/Injector -> Broadcasting", msg, "to the network")
        return self.broadcast(msg, network_tuple)
