import threading
import server


class NetworkInjector(threading.Thread):

    @staticmethod
    def broadcast(message, network_tuple):
        sockets = network_tuple[0]  # List of clients we need to broadcast to
        for client in sockets:
            server.Server.send(client, message)  # For each of them send the given message( = Broadcast)

    def collect(self, network_tuple):
        while 1:
            msg = str(input("Please enter flag to inject into network:  "))
            print("Server/Injector -> Broadcasting", msg, "to the network")
            self.broadcast(msg, network_tuple)

    def init(self, network_tuple):
        injector = threading.Thread(target=self.collect, args=(network_tuple,), name='Injector')
        injector.start()
    ''' TODO: READ: Implement some way to kill other network injectors before starting a new one on connection;
        It's a waste of threads, creates race conditions, and does other nasty stuff!'''
