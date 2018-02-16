# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client
port = 3705


def init():
    x = client.Client()
    x.initialize(port=port, network_architecture="Complete", remote_addresses=None)


if __name__ == "__main__":
    init()
