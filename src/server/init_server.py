# Python 3.6.2
# Script automating the starting of the client individually.

import server
port = 3705


def init():
    x = server.Server()
    x.initialize(port=port, network_architecture="complete", method="socket", listening=True, network_injection=True)


if __name__ == "__main__":
    init()
