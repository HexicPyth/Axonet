# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client
import json

port = 3705

with open("client_configuration.json") as client_configuration:
    client_config_data = json.load(client_configuration)
    for var in client_config_data:
        print(var, json.loads(var))



def init(network_architecture):
    x = client.Client()
    x.initialize(port=port, net_architecture=network_architecture, remote_addresses=None,
                 command_execution=True, default_log_level="Info", modules=["corecount"], net_size=4,
                 assigned_part_numbers=[])


if __name__ == "__main__":
    init("mesh")
