# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client

port = 3705


def init(network_architecture):
    x = client.Client()
    x.initialize(port=port, net_architecture=network_architecture, remote_addresses=None,
                 command_execution=True, default_log_level="Info", modules=["corecount"], net_size=4,
                 assigned_part_numbers=[])


if __name__ == "__main__":
    init("mesh")
