import multiprocessing
import sys
import os
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

    def send(self, sock, msg, network_tuple, signing=True):
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
                index = network_tuple[0].index(sock)
                socket_to_disconnect = network_tuple[0][index]
                address = network_tuple[1][index]
                return address

    def broadcast(self, message, network_tuple):
        global current_message
        sockets = network_tuple[0]  # List of clients we need to broadcast to
        return_code = 0
        for client in sockets:

            index = network_tuple[0].index(client)
            address = network_tuple[1][index]  # Find the address of the socket we're sending to

            print("Sending: "+"'"+message+"'"+" to "+address)  # print("Sending: '(message)' to (address)")
            y = self.send(client, message, network_tuple)  # For each of them send the given message
            if type(y) == str:
                return_code = y

        current_message = None  # reset current message
        return return_code

    def kill(self):
        print("Injector -> Terminate() : Reluctantly terminating myself... * cries to the thought of SIGKILL *")
        self.terminate()
        return

    def init(self, network_tuple):
        #fn = sys.stdin.fileno()
        #sys.stdin = os.fdopen(fn)
        msg = str(input("Please enter flag to inject into network:  "))
        print("Server/Injector -> Broadcasting", msg, "to the network")
        return self.broadcast(msg, network_tuple)
        #injector = multiprocessing.Process(target=self.collect, args=(network_tuple, fn,), name='Injector')
        #injector.start()
