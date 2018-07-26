# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client
port = 3705


def init():
    x = client.Client()
    x.initialize(port=port, net_architecture="Complete", remote_addresses=None,
                 command_execution=True, default_log_level="Debug", modules=["corecount"])


if __name__ == "__main__":
    init()
