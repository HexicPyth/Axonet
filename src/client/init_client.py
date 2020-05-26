# Python 3.6.2
# Script automating the starting of the client individually.
# Initialize the client
import client
import json
import os

# Switch to the directory containing init_client.py
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)

with open("client_configuration.json") as client_configuration:
    """Sets each variable equal to the value given in the client_configuration.json file"""

    client_config_data = json.load(client_configuration)
    port = client_config_data["port"]
    network_architecture = client_config_data["network_architecture"]
    remote_addresses = client_config_data["remote_addresses"]
    command_execution = client_config_data["command_execution"]
    default_log_level = client_config_data["default_log_level"]
    modules = client_config_data["modules"]
    net_size = client_config_data["net_size"]
    directory_server = client_config_data["directory_server"]


def init():
    x = client.Client()
    x.initialize(port=port, net_architecture=network_architecture, remote_addresses=remote_addresses,
                 command_execution=command_execution, default_log_level=default_log_level, modules=modules,
                 net_size=net_size, input_directory_server=directory_server)


if __name__ == "__main__":
    init()
