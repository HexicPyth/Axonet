import os
import sys
import json

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
os.chdir("../../../")

from src.client import client



# Configure permanent port
def change_port(new_port):
    try:
        if int(new_port):
            with open('client_configuration.json', 'r')as client_configuration:
                client_config = json.load(client_configuration)
                client_config['port'] = int(new_port)
                client_configuration.close()

            with open('client_configuration.json', 'w')as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                client_configuration.close()

    except (ValueError, TypeError):
        print("That is not a valid port")


# Configure permanent network size
def config_net_size(new_net_size):
    try:
        if int(new_net_size):
            with open('client_configuration.json', 'r')as client_configuration:
                client_config = json.load(client_configuration)
                client_config['net_size'] = int(new_net_size)
                client_configuration.close()

            with open('client_configuration.json', 'w')as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                print(client_config['port'])
                client_configuration.close()

    except (ValueError, TypeError):
        print("That is not a valid port")


# Configure permanent network_architecture
def config_network_architecture(new_net_architecture):
    if type(new_net_architecture) == str:
        with open('client_configuration.json', 'r')as client_configuration:
            client_config = json.load(client_configuration)
            client_config['network_architecture'] = new_net_architecture
            client_configuration.close()

        with open('client_configuration.json', 'w')as client_configuration:
            client_configuration.seek(0)
            json.dump(client_config, client_configuration)
            print(client_config['port'])
            client_configuration.close()


def config_remote_addresses(new_remote_addresses):
    try:
        new_remote_addresses_list = new_remote_addresses.split(' ')

        if new_remote_addresses_list[0] == "None":

            with open('client_configuration.json', 'r') as client_configuration:
                client_config = json.load(client_configuration)
                client_config['remote_addresses'] = [""]
                print(client_config)
                client_configuration.close()

            with open('client_configuration.json', 'w') as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                client_configuration.close()

        else:
            with open('client_configuration.json', 'r') as client_configuration:
                client_config = json.load(client_configuration)
                client_config['remote_addresses'] = new_remote_addresses_list
                client_configuration.close()

            with open('client_configuration.json', 'w') as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                client_configuration.close()

    except (ValueError, TypeError):
        print("That is not a valid port")


def config_directory_server(new_directory_server):
    with open('client_configuration.json', 'r')as client_configuration:
        client_config = json.load(client_configuration)
        client_config['directory_server'] = new_directory_server
        client_configuration.close()

    with open('client_configuration.json', 'w')as client_configuration:
        client_configuration.seek(0)
        json.dump(client_config, client_configuration)
        print(client_config['port'])
        client_configuration.close()


# main function called from client
def config_argument(arguments, sub_node, log_level, nodeConfig):
    from src.inter.modules import primitives
    _primitives = primitives.Primitives(sub_node, log_level)
    Client = client.Client()

    print(arguments, "there are the arguments")
    try:
        setting = arguments[0]  # permanent or a value for a temporary config
        setting_value = arguments[1]

    except IndexError:
        print("There are no more arguments in the message!")
        return None

    if setting == "network_size" or setting == "net_size":

        try:
            new_network_size = int(setting_value)
            new_nodeConfig = Client.write_nodestate(nodeConfig, 7, new_network_size, void=False)
            _primitives.log("Successfully set network_size to: " + str(new_network_size), in_log_level="Info")
            return new_nodeConfig
        except TypeError:

            _primitives.log("config: target value not int; ignoring...", in_log_level="Warning")

    elif setting == "network_architecture":
        # Changes from any architecture --> mesh must be done while network size <= 2
        # any architecture --> fully-connected should always work

        new_network_architecture = setting_value

        if type(new_network_architecture) == str:
            new_nodeConfig = Client.write_nodestate(nodeConfig, 8, new_network_architecture, void=False)
            _primitives.log("Successfully set network_architecture to: " + new_network_architecture,
                            in_log_level="Info")
            return new_nodeConfig
        else:
            print("The new network architecture is not a string")

    elif setting == "port":
        try:

            if int(setting_value):
                new_nodeConfig = Client.write_nodestate(nodeConfig, 0, setting_value, void=False)
                return new_nodeConfig

        except (ValueError, TypeError):
            print("That is not a valid port")


    elif setting == "command execution":
        new_nodeConfig = Client.write_nodestate(nodeConfig, 1, False, void=False)
        print("NOT ENABLING A REMOTE CODE EXECUTION EXPLOIT, DUFUS!")
        return new_nodeConfig

    elif setting == "directory_server":
        new_directory_server = setting_value
        new_nodeConfig = Client.write_nodestate(nodeConfig, 10, new_directory_server, void=False)
        return new_nodeConfig

    # Permanent Setting Configurations
    elif setting == "permanent":

        try:

            permanent_setting_data = arguments[2]
        except IndexError:

            print("There are no more arguments in the message!")
            return

        if setting_value == "port":
            change_port(permanent_setting_data)

        elif setting_value == "network_architecture":
            config_network_architecture(permanent_setting_data)
            pass

        elif setting_value == "remote_addresses":
            config_remote_addresses(permanent_setting_data)
            pass

        elif setting_value == "command_execution":
            pass

        elif setting_value == "default_log_level":
            pass

        elif setting_value == "modules":
            pass

        elif setting_value == "network_size" or setting_value == "net_size":
            config_net_size(permanent_setting_data)
            pass

        elif setting_value == "directory_server":
            config_directory_server(permanent_setting_data)

        else:
            print("Error \"" + setting_value + "\" isn't correct syntax")