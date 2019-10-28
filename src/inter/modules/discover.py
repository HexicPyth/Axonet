import os
import sys
import secrets

this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../client/')
sys.path.insert(0, '../../server/')
sys.path.insert(0, '../../inter/modules/')
sys.path.insert(0, '../../misc/')

import primitives

no_prop = "ffffffffffffffff"


def initiate(net_tuple):
    """ Called from the network injector when it receives a $discover: flag"""
    import inject

    op_id = secrets.token_hex(8)
    print("Discover -> Info: Initiating peer discovery (ring --> mesh bootstrapping stage 1)")

    injector = inject.NetworkInjector()
    injector.broadcast("vote:discovery-"+op_id, net_tuple)


def respond_start(net_tuple, op_id, cluster_rep):
    """Called by the client's listener_thread after the 'discovery' election is complete"""
    import inject
    if cluster_rep:
        injector = inject.NetworkInjector()
        injector.broadcast("newpage:"+op_id, net_tuple)  # Create a pagefile to store peer addresses in
        injector.broadcast("sharepeers:"+op_id, net_tuple)  # Instruct nodes to append peer addresses to this pagefile




def start(net_tuple, op_id):
    """Called after addresses are written to page [op-id] """
    import inject

    injector = inject.NetworkInjector()
    injector.broadcast("fetch:" + op_id, net_tuple)  # Synchronise discovered addresses across distributed filesystem...

