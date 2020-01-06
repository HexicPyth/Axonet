import os
import sys
import json

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../../client/')
sys.path.insert(0, '../../../server/')
sys.path.insert(0, (os.path.abspath('../../inter/misc')))
import primitives


def change_port(arguments):
    try:
        if int(arguments[2]):
            with open('client_configuration.json', 'r')as client_configuration:
                client_config = json.load(client_configuration)
                client_config['port'] = int(arguments[2])
                client_configuration.close()
            with open('client_configuration.json', 'w')as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                client_configuration.close()

    except (ValueError, TypeError):
        print("That is not a valid port")


def config_net_size(arguments):
    try:
        if int(arguments[2]):
            with open('client_configuration.json', 'r')as client_configuration:
                client_config = json.load(client_configuration)
                client_config['net_size'] = int(arguments[2])
                client_configuration.close()
            with open('client_configuration.json', 'w')as client_configuration:
                client_configuration.seek(0)
                json.dump(client_config, client_configuration)
                print(client_config['port'])
                client_configuration.close()

    except (ValueError, TypeError):
        print("That is not a valid port")


def config_argument(arguments, sub_node, log_level):
    _primitives = primitives.Primitives(sub_node, log_level)
    print(arguments, "there are the arguments")
    if arguments[0] == "network_size":

        try:
            new_network_size = int(arguments[1])
            network_size = new_network_size
            _primitives.log("Successfully set network_size to: " + str(network_size), in_log_level="Info")

        except TypeError:

            _primitives.log("config: target value not int; ignoring...", in_log_level="Warning")

    elif arguments[0] == "network_architecture":
        # Changes from any architecture --> mesh must be done while network size <= 2
        # any architecture --> fully-connected should always work

        new_network_architecture = arguments[1]

        if type(new_network_architecture) == str:
            network_architecture = new_network_architecture
            _primitives.log("Successfully set network_architecture to: " + network_architecture,
                            in_log_level="Info")
    elif arguments[0] == "permanent":
        if arguments[1] == "port":

            change_port(arguments)
        elif arguments[1] == "network_architecture":
            pass
        elif arguments[1] == "remote_addresses":
            pass
        elif arguments[1] == "command_execution":
            pass
        elif arguments[1] == "default_log_level":
            pass
        elif arguments[1] == "modules":
            pass
        elif arguments[1] == "network_size" or arguments[1] == "net_size":
            config_net_size(arguments)
            pass
        else:
            print("Error \"" + arguments[1] + "\" isn't correct syntax")
