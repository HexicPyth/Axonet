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

_primitives = primitives.Primitives('Client', 'Debug')


def initiate(net_tuple, arguments):
    _client = client.Client()

    """ Called from the network injector when it receives a $vote:(reason) input"""
    os.chdir(this_dir)
    import inject
    injector = inject.NetworkInjector()
    reason = arguments[0]

    # Start an election
    injector.broadcast("vote:"+reason, net_tuple)


def respond_start(reason, nodeState):
    _client = client.Client()

    """Called by the client's listener_thread when it received a vote: flag"""

    new_nodestate = nodeState

    election_list = nodeState[9]
    new_nodestate = _client.write_nodestate(nodeState, 10, True, void=False)

    election_tuple_index = _primitives.find_election_index(election_list, reason)

    # If this node hasn't yet initialized it's election_list for (reason, "TBD") or (reason, representative)
    if election_tuple_index == -1:

        election_tuple = (reason, "TBD")
        election_list.append(election_tuple)
        election_list = list(set(election_list))  # Remove any duplicates

        new_nodestate = _client.write_nodestate(new_nodestate, 9, election_list, void=False)

        # Generate a campaign: integer and call campaign for (reason, localhost)

        campaign_int = random.randint(1, 2 ** 128)
        local_ip = _primitives.get_local_ip()

        new_nodestate = _client.write_nodestate(new_nodestate, 7, campaign_int, void=False)

        _primitives.log("Campaigning for " + str(campaign_int), in_log_level="Info")

        campaign_msg = _client.prepare("campaign:" + reason + ":" + str(campaign_int)+":"+local_ip)
        _client.broadcast(campaign_msg, do_mesh_propagation=True)

    else:

        pass  # Don't disrupt ongoing election...

    return new_nodestate
