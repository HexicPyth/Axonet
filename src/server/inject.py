import server
import multiprocessing
import sys
import os


class NetworkInjector(multiprocessing.Process):

    @staticmethod
    def broadcast(message, network_tuple):
        sockets = network_tuple[0]  # List of clients we need to broadcast to
        for client in sockets:

            index = network_tuple[0].index(client)
            address = network_tuple[1][index]  # Find the address of the socket we're sending to

            print("Sending: "+"'"+message+"'"+" to "+address)  # print("Sending: '(message)' to (address)")
            server.Server.send(client, message)  # For each of them send the given message( = Broadcast)

    def collect(self, network_tuple, fileno):
        sys.stdin = os.fdopen(fileno)
        while 1:
            msg = str(input("Please enter flag to inject into network:  "))
            print("Server/Injector -> Broadcasting", msg, "to the network")
            self.broadcast(msg, network_tuple)

    def init(self, network_tuple):
        fn = sys.stdin.fileno()
        injector = multiprocessing.Process(target=self.collect, args=(network_tuple, fn,), name='Injector')
        injector.start()
