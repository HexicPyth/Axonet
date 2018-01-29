import multiprocessing
import sys
import os
import struct
import datetime
from hashlib import sha3_224


class NetworkInjector(multiprocessing.Process):

    @staticmethod
    def prepare(message):  # Process our message for broadcasting
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

    def send(self, sock, msg, signing=True):
        if signing:
            msg = self.prepare(msg).encode('utf-8')
        else:
            msg.encode('utf-8')

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        sock.sendall(msg)

    def broadcast(self, message, network_tuple):
        sockets = network_tuple[0]  # List of clients we need to broadcast to
        for client in sockets:

            index = network_tuple[0].index(client)
            address = network_tuple[1][index]  # Find the address of the socket we're sending to

            print("Sending: "+"'"+message+"'"+" to "+address)  # print("Sending: '(message)' to (address)")
            self.send(client, message)  # For each of them send the given message( = Broadcast)

    def collect(self, network_tuple, fileno):
        sys.stdin = os.fdopen(fileno)
        while 1:
            msg = str(input("Please enter flag to inject into network:  "))
            print("Server/Injector -> Broadcasting", msg, "to the network")
            self.broadcast(msg, network_tuple)

    def kill(self):
        print("FlagThread - Terminate() : Reluctantly terminating myself... * cries to the thought of SIGKILL *")
        self.terminate()
        return

    def init(self, network_tuple):
        fn = sys.stdin.fileno()
        injector = multiprocessing.Process(target=self.collect, args=(network_tuple, fn,), name='Injector')
        injector.start()
