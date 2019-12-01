import os
import sys
import secrets

this_dir = os.path.dirname(os.path.realpath(__file__))

os.chdir(this_dir)

sys.path.insert(0, (os.path.abspath('../../client')))
sys.path.insert(0, (os.path.abspath('../../server')))
sys.path.insert(0, (os.path.abspath('../../inter/modules')))
sys.path.insert(0, (os.path.abspath('../../inter/misc')))

import primitives

def initiate(net_tuple):
    """ Called from the network injector when it receives a $discover: flag"""
    os.chdir(this_dir)
    import inject

    op_id = secrets.token_hex(8)
    print("Discover -> Info: Initiating peer discovery (ring --> mesh bootstrapping stage 1)")

    injector = inject.NetworkInjector()
    injector.broadcast("vote:discovery-"+op_id, net_tuple)


def respond_start(nodeState, op_id, cluster_rep):
    """Called by the client's listener_thread after the 'discovery' election is complete"""

    print('Current directory: '+this_dir)
    import client
    _client = client.Client()

    os.chdir(this_dir)

    net_tuple = nodeState[0]

    if cluster_rep:
        # Create a pagefile to store peer addresses in
        new_nodeState = _client.broadcast("newpage:"+op_id, in_nodeState=nodeState)

        # Instruct nodes to append peer addresses to this pagefile
        new_nodeState = _client.broadcast("sharepeers:"+op_id, in_nodeState=new_nodeState, do_mesh_propagation=False)

        return new_nodeState

    else:

        # Do nothing...
        return nodeState


def start(net_tuple, op_id, cluster_rep):
    """Called after addresses are written to page [op-id] """
    import client

    _client = client.Client()

    # Synchronise discovered addresses across distributed filesystem...
    if cluster_rep:
        print("!?!?!?!?! We are cluster rep!!!")
        _client.broadcast(_client.prepare("fetch:" + op_id + ":discovery"), do_mesh_propagation=False)

