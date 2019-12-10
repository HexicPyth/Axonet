# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client
import json

port = 3705

with open("client_configuration.json") as client_configuration:
    client_config_data = json.load(client_configuration)
    port = client_config_data["port"]
    remote_addresses = client_config_data["remote_addresses"]
    command_execution = client_config_data["command_execution"]
    default_log_level = client_config_data["default_log_level"]
    modules = client_config_data["modules"]
    net_size = client_config_data["net_size"]


def init(network_architecture):
    x = client.Client()
    x.initialize(port=port, net_architecture=network_architecture, remote_addresses=remote_addresses,
                 command_execution=command_execution, default_log_level=default_log_level, modules=modules,
                 net_size=net_size)


if __name__ == "__main__":
    init("mesh")
