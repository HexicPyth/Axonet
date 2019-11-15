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


def initiate(net_tuple, arguments):
    """ Called from the network injector when it receives a $vote:(reason) input"""
    os.chdir(this_dir)
    import inject
    injector = inject.NetworkInjector()
    reason = arguments[0]

    # Start an election
    injector.broadcast("vote:"+reason, net_tuple)


def respond_start(message, nodeState, ongoing_election):
    """Called by the client's listener_thread when it received a vote: flag"""

    new_nodestate = nodeState

    if not ongoing_election:
        election_list = nodeState[9]
        new_nodestate = _client.write_nodestate(nodeState, 10, True, void=False)

        reason = message[5:]

        election_tuple = (reason, "TBD")
        election_list.append(election_tuple)
        election_list = list(set(election_list))  # Remove any duplicates

        new_nodestate = _client.write_nodestate(new_nodestate, 9, election_list, void=False)

        campaign_int = random.randint(1, 2 ** 128)
        new_nodestate = _client.write_nodestate(nodeState, 7, campaign_int, void=False)

        _primitives.log("Campaigning for " + str(campaign_int), in_log_level="Info")
        campaign_msg = _client.prepare("campaign:" + reason + ":" + str(campaign_int))
        _client.broadcast(campaign_msg, do_mesh_propagation=True)

    return new_nodestate
