import random
import collections
import pprint
import string

# hosts = [item.strip('\n') for item in open("hosts.bin", "r").readlines()][:network_size]


def reseed():
    # Generate a deterministic sequence of RNG seeds from one initial seed
    global current_seed

    random.seed(current_seed)  # Apply the previous seed

    # Use the previous seed to generate a new seed
    # which will be applied next time this function is called
    current_seed = random.randint(0,9999999999)


def gen_peers(network_graph, node, c_ext, verbose=False):
    reseed()
    potential_peers = list(hosts)  # make a copy which we can safely mutilate without altering the global hosts list

    potential_peers.remove(node)  # Remove ourselves from the hosts list so we don't try to connect to ourselves.
    our_peers = network_graph[node]  # Lookup a list of any peers we're already connected to

    for i in range(0, c_ext):

        # Remove everything were already connected to from the list of potential peers
        potential_peers = [peer for peer in potential_peers if peer not in our_peers]

        if verbose:
            print("Choosing peer from: " + str(potential_peers))

        try:
            selected_peer = random.choice(potential_peers)

        except IndexError:
            # c_ext/N must be very large(~1); this node is already connected to N-1 nodes; not connecting to any more...
            return network_graph

        # Connect to a random peer
        if selected_peer not in our_peers:
            our_peers.append(selected_peer)

            if verbose:
                print("Connected " + node + " --> " + selected_peer + " with seed: " + str(current_seed))

            # Make sure we don't try to connect to same peer again next time
            potential_peers.remove(selected_peer)

        # They're already connected to us, don't try to connect again (connections are bidirectional)
        else:
            potential_peers.remove(selected_peer)

            if verbose:
                print("Tried to connect " + node + " --> " + selected_peer + " with seed: " + str(current_seed)
                      + " but " + node + " is already connected to "+selected_peer)

        # Connections are bidirectional; connect the selected random peer to us...
        their_peers = network_graph[selected_peer]
        if node not in their_peers:
            their_peers.append(node)
            network_graph.update({selected_peer: their_peers})

            if verbose:
                print("\t (Connected " + selected_peer + " to " + node + ")")

        # Reseed with next seed in sequence
        reseed()

    # Write changes!
    network_graph.update({node: our_peers})

    return network_graph


def gen_network(in_network, c_ext):
    network_tree = {}

    # Make an empty graph
    for host in hosts:
        network_tree.update({host: []})

    for node in in_network:
        network_tree = gen_peers(network_tree, node, c_ext)

    return network_tree


def clear_terminal():
    print('\n' * 10)


def pretty_print(in_network):
    for node, peers in in_network.items():
        print("{}:  {}".format(node, peers))


def compress_network(in_network, new_network_size, max_c_ext):
    # To reduce a larger network to a smaller one:

    # 1. Trim excess hosts from end of hosts list
    # 2. Iterate through network graph and terminate connections to trimmed hosts
    # 3. Append valid network trees into a new graph

    new_network = {}
    network_hosts = list(in_network.keys())

    old_network_size = len(network_hosts)
    hosts_to_trim = old_network_size-new_network_size
    trimmed_hosts = []

    # 1. Trim excess hosts from end of hosts list
    for i in range(0, hosts_to_trim):
        trimmed_hosts.append(network_hosts[-1])
        network_hosts = network_hosts[:-1]

    # 2. Iterate through network graph and terminate connections to trimmed hosts
    for host in network_hosts:
        peers = [peer for peer in in_network[host] if peer not in trimmed_hosts]

        # 3. Append valid network trees into a new graph
        new_network.update({host: peers})

    return scale_down_network_connectedness(new_network, max_c_ext)


def scale_down_network_connectedness(in_network, max_c_ext):
    # Scale down a network to a lower c_ext value

    # 1. Find most connected node
    # 2. Find most connected peers of most connected node
    # 3. Disconnect mose connected node from its most connected peer
    # 4. Repeat until c_ext is low enough

    new_network = in_network
    while classify_network(new_network)[1] > max_c_ext:

        # 1. Find most connected node

        host_to_number_of_peers = {}
        for host in in_network.keys():
            host_to_number_of_peers.update({host: len(new_network[host])})

        # Sort nodes by connectedness. Most connected node will be element 0.
        hosts_sorted_by_peer_count_descending = list({key: value for key, value in reversed(
            sorted(host_to_number_of_peers.items(), key=lambda item: item[1]))}.keys())

        # (Its this one)
        most_connected_node = hosts_sorted_by_peer_count_descending[0]
        print("Removing a connection from most connected node: "+most_connected_node)

        # 2. Find peers of most connected node
        most_connected_node_peers = new_network[most_connected_node]

        peers_of_most_connected_node_to_peer_count = {}
        for node in most_connected_node_peers:
            peers_of_most_connected_node_to_peer_count.update({node: host_to_number_of_peers[node]})

        # Sort them by connectedness
        peers_of_most_connected_node_by_peer_count_descending = list({key: value for key, value in reversed(
            sorted(peers_of_most_connected_node_to_peer_count.items(), key=lambda item: item[1]))}.keys())

        # 3. Disconnect mose connected node from its most connected peer
        print("disconnecting " + peers_of_most_connected_node_by_peer_count_descending[0]
              + " from " + most_connected_node)

        # Disonnect most connected node from its most connected peer
        most_connected_peer_of_most_connected_node = peers_of_most_connected_node_by_peer_count_descending[0]
        peers_of_most_connected_node_by_peer_count_descending.pop(0)
        new_network.update({most_connected_node: peers_of_most_connected_node_by_peer_count_descending})

        # Connections are bidirectional; disconnect the other way around too
        peers_of_most_connected_peer_of_most_connected_node = in_network[most_connected_peer_of_most_connected_node]
        peers_of_most_connected_peer_of_most_connected_node.remove(most_connected_node)

        new_network.update(
            {most_connected_peer_of_most_connected_node: peers_of_most_connected_peer_of_most_connected_node})

    return new_network


def classify_network(in_network):
    number_of_unidirectional_edges = 0
    in_network_size = len(in_network.keys())
    for host in in_network.keys():
        peers = in_network[host]
        number_of_unidirectional_edges += len(peers)

    equivalent_c_ext = round(number_of_unidirectional_edges/in_network_size, 2)
    print("Size: " + str(in_network_size) + " c_ext: " + str(equivalent_c_ext))
    return in_network_size, equivalent_c_ext


# See https://drive.google.com/file/d/1INYHo6JnkKYqLyNVMg2fRVyJKrPShAfa/view?usp=sharing for
# a simple demonstration of how the mesh is generated, and read the comments below to get a deeper understanding
# of how that simple algorithm(defined in gen_peers()) is modified to provide scalability.

# The default parameters are good for network sizes between 15-100 with a good amount of redundancy
# (on average, each node is connected to 5 others) and allows adding up to 85 additional nodes(15+85=100 total)
# before these settings should be modified. There is nothing special about the default value of initial_seed.

# This is a random number which seeds the RNG to ultimately determine the exact network architecture of the finished
# network. It can be set to any value, although more entropy is better. It must be the same across all nodes in order
# for each node to generate the same network.
initial_seed = 6847832947
current_seed = initial_seed

# This is the upper bound on your network's scalability. It sets the maximum number of nodes which can be added
# to the network before the network architecture would have to change dramatically to provide them reasonable
# connectedness. Counting how many nodes you have and multiply that by 2 to 3 seems like a good option :)
# (caveat: the complexity of the network generator is roughly O(n^2) so larger networks will consume more CPU
# resources, don't make this over 300 or so unless you want to crash the Pis :)) Also, if this is too high
# you will have to crank the max_network_c_ext up very high to achieve reasonable connectedness(redundancy)
# which creates a large performance penalty for the network generator.
max_network_size = 100

# This controls the maximum connectedness of your scalable mesh network. Using the comment below for network_c_ext
# to pick a reasonable value, multiply it by some number >~2.7; round to nearest integer
# (The network compressor cannot make a network with a c_ext greater than about 3/8 of the input network c_ext)
max_network_c_ext = 20

# Represents an generalized arbitrary sized network as a collection of nodes['1', '2', '3', .... 'N']
# You may assign these generalized hostname to IP addresses however you wish
hosts = [str(x) for x in range(1, max_network_size + 1)]

max_network = gen_network(hosts, max_network_c_ext)

# This is the size of your network. If max_network_size is significantly larger than it, then
# it can be moderately increased or decreased without significantly impacting the network architecture
# (Yay scalability!)
network_size = 15

# This controls the connectedness of your network. It represents how many other nodes each node connects to to form
# the output mesh. If c_ext = network_size-1 then the network is "fully complete" meaning all nodes are connected to
# all other nodes. This is the most redundant option, but it is very inefficient and it buts a significant burden
# on your networking equipment which would have to handle (N^2)-N simultaneous connections where N = network size.
# (that's 2550 connections for N=51!)
# The ratio of c_ext to network size roughly determines (on average) the number of nodes which would have to go down
# before packet delivery to the remaining nodes is impacted. For example, for N=20 and c_ext=5, on average
# (depends on initial seed) 25% of the nodes(5 of them) would have to go down before packet delivery between the
# remaining 15 was significantly impacted. Recommended value is somewhere in the range of 5%-40% of your network size,
# anything higher than that yields diminishing returns.
network_c_ext = 5

# The network compressor turns the maximum size (max_network_size) network into a smaller one which can be
# incrementally scaled up to max_network_size by increasing network_size without significantly altering the
# network architecture. As a side effect of reducing the network size, the ratio of equivalent c_ext to network
# size increase significantly, so the scale_down_network_connectedness algorithm is used to reduce it c_ext to some
# sane arbitrary value specified by network_c_ext. (An N=100 c_ext = 20 network is pretty connected already, a
# compressed N=30 c_ext=18-ish network is pushing the limits of practicality a bit...) scale_down_network_connectedness
# is lossy and has a hard time reducing the c_ext to values higher than about 3/8 of the input network c_ext,
# hence why max_c_ext should be >~2.7x larger than the target one.
compressed_network = compress_network(max_network, network_size, network_c_ext)

# Print the network to stdout as a 2D array displaying the network as a series of trees which connects a parent node
# (a host) to some number of child nodes(peers). The collection of all of these trees represents the finished network
# graph.
pretty_print(compressed_network)

# Tells you the network_size and approximate c_ext of the finished network. the c_ext should be slightly less than or
# equal to the value specified by network_c_ext
classify_network(compressed_network)

