import os
import sys
import random

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)

sys.path.insert(0, (os.path.abspath('../../client')))
sys.path.insert(0, (os.path.abspath('../../server')))

import primitives
import client

_client = client.Client()
_primitives = primitives.Primitives('Client', 'Debug')


def respond_start(message, nodeState):
    """Called by the client's listener_thread when it received a vote: flag"""
    os.chdir(this_dir)

    net_tuple = nodeState[0]
    election_list = nodeState[9]

    arguments = _primitives.parse_cmd(message)  # arguments[0] = op_id = name of pagefile
    op_id = arguments[0]

    new_module_loaded = "discovery"

    nodeState = _client.write_nodestate(nodeState, 5, new_module_loaded, void=False)  # set module_loaded = "discover"
    nodeState = _client.write_nodestate(nodeState, 12, True, void=False)  # Set network propagation mode to mesh

    data = _primitives.get_local_ip()

    print("Local IP: " + data)

    print(os.getcwd())
    file_path = os.path.abspath("../../inter/mem/" + op_id + ".bin")
    raw_lines = list(set(open(file_path, "w+").readlines()))


    existing_lines = [raw_line for raw_line in raw_lines
                      if raw_line != "\n" and raw_line[:2] != "##"]

    addresses = [item[1] for item in net_tuple if item not in existing_lines]
    
    for address in addresses:
        data += "\n"+address

    print("Writing Data: " + data)

    # Write it to page [op_id]
    _client.write_to_page(op_id, data, signing=False)

    # Callback to discover module
    is_cluster_rep = (_primitives.find_representative(election_list, "discovery-" + op_id)
                      == _primitives.get_local_ip())

    print("Is cluster rep: " + str(is_cluster_rep))

    return nodeState, op_id, is_cluster_rep
