import random
import string
# hosts = [item.strip('\n') for item in open("hosts.bin", "r").readlines()][:network_size]
# All of the comments below rely on your understanding of the content in
# https://drive.google.com/file/d/1INYHo6JnkKYqLyNVMg2fRVyJKrPShAfa/view?usp=sharing
# (namely the concept of c_ext and the simple mesh network bootstrapping algorithm described there ^^)
# so, read that first.


def reseed():
    # Generate a deterministic sequence of RNG seeds from one initial seed
    global current_seed

    random.seed(current_seed)  # Apply the previous seed

    # Use the previous seed to generate a new seed
    # which will be applied next time this function is called
    current_seed = random.randint(0, 2**128)


def gen_peers(network_graph, node, c_ext, verbose=False):
    reseed()
    potential_peers = list(max_hosts)  # make a copy which we can safely mutilate without altering the global hosts list

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


def generate_uncompressed_mesh(in_network, c_ext):
    network_tree = {}

    # Make an empty graph
    for host in max_hosts:
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


def scale_down_network_connectedness(in_network, max_c_ext, verbose=False):
    # Scale down a network to a lower c_ext value

    # 1. Find most connected node
    # 2. Find most connected peers of most connected node
    # 3. Disconnect mose connected node from its most connected peer
    # 4. Repeat until c_ext is low enough

    new_network = in_network
    while classify_network(new_network, quiet=True)[1] > max_c_ext:

        # 1. Find most connected node

        host_to_number_of_peers = {}
        for host in in_network.keys():
            host_to_number_of_peers.update({host: len(new_network[host])})

        # Sort nodes by connectedness. Most connected node will be element 0.
        hosts_sorted_by_peer_count_descending = list({key: value for key, value in reversed(
            sorted(host_to_number_of_peers.items(), key=lambda item: item[1]))}.keys())

        # (Its this one)
        most_connected_node = hosts_sorted_by_peer_count_descending[0]
        if verbose:
            print("Removing a connection from most connected node: "+most_connected_node)

        # 2. Find peers of most connected node
        most_connected_node_peers = new_network[most_connected_node]

        peers_of_most_connected_node_to_peer_count = {}
        for node in most_connected_node_peers:
            peers_of_most_connected_node_to_peer_count.update({node: host_to_number_of_peers[node]})

        # Sort them by connectedness
        peers_of_most_connected_node_by_peer_count_descending = list({key: value for key, value in reversed(
            sorted(peers_of_most_connected_node_to_peer_count.items(), key=lambda item: item[1]))}.keys())

        if verbose:
            print("disconnecting " + peers_of_most_connected_node_by_peer_count_descending[0]
                  + " from " + most_connected_node)

        # 3. Disconnect mose connected node from its most connected peer
        most_connected_peer_of_most_connected_node = peers_of_most_connected_node_by_peer_count_descending[0]
        peers_of_most_connected_node_by_peer_count_descending.pop(0)
        new_network.update({most_connected_node: peers_of_most_connected_node_by_peer_count_descending})

        # Connections are bidirectional; disconnect the other way around too
        peers_of_most_connected_peer_of_most_connected_node = in_network[most_connected_peer_of_most_connected_node]
        peers_of_most_connected_peer_of_most_connected_node.remove(most_connected_node)

        new_network.update(
            {most_connected_peer_of_most_connected_node: peers_of_most_connected_peer_of_most_connected_node})

    return new_network


def classify_network(in_network, quiet=False):
    number_of_unidirectional_edges = 0
    in_network_size = len(in_network.keys())
    for host in in_network.keys():
        peers = in_network[host]
        number_of_unidirectional_edges += len(peers)

    # If you count the total number of one-way connections and divide that by the network size you'll get something
    # that roughly approximates the c_ext value of an arbitrary network
    # (it actually equals the c_ext value if you use the network generator gen_network() from above)
    equivalent_c_ext = round(number_of_unidirectional_edges/in_network_size, 2)
    if not quiet:
        print("Size: " + str(in_network_size) + " c_ext: " + str(equivalent_c_ext))
    return in_network_size, equivalent_c_ext


def get_broadcast_ttl(in_network, in_hosts, source, verbose=True):

    # Determine what time-to-live value is needed for a message to be received by all nodes if it is continuously
    # broadcast by all receiving nodes who haven't already broadcast the message until ttl=0
    levels = []
    in_hosts = [hostname + "-0" for hostname in in_hosts]  # Initialize all levels at zero

    hosts_to_discover = in_hosts

    source_queue = []
    discovered_hosts = []
    new_source = source + "-0"

    source_peers = in_network[source]

    while hosts_to_discover:
        new_source_without_level_suffix = new_source.split("-")[0]
        source_peers = in_network[new_source_without_level_suffix]

        if verbose:
            print("Undiscovered hosts: " + str(hosts_to_discover))
            print("Peers of " + new_source + ": " + str(source_peers))

        for peer in source_peers:
            if peer not in discovered_hosts:
                if verbose:
                    print('Discovered ' + peer, end=' ')
                    print("(Source: " + new_source + ")")

                if peer+"-0" in hosts_to_discover:
                    hosts_to_discover.remove(peer + "-0")  # All nodes in host_to_discover list have level 0

                    # We keep track of the current level by incrementing an integer to the end of the hostnames
                    # (preceded by a dash) of each nodes peers corresponding to the level of the source host + 1
                    # each time we branch off from parent node. This is a very unsatisfying solution but ¯\_(ツ)_/¯
                    source_layer = new_source[-1]
                    peer += "-"+str(int(source_layer)+1)

                    discovered_hosts.append(peer)

                if peer not in source_queue:
                    source_queue.append(peer)
        try:
            next_source = source_queue[0]
            source_queue.remove(next_source)
        except IndexError:
            break
        new_source = next_source

    if verbose:
        print(discovered_hosts)
        print(hosts_to_discover)

    levels = [hostname.split("-")[1] for hostname in discovered_hosts]
    ttl = max(levels)
    if verbose:
        print("Message must be broadcast (from node "+source + ") with ttl="+ttl+" to reach all nodes.")
    return int(ttl)

    # while hosts_to_discover is not empty, remove all nodes we discover by traversing the graph


# See https://drive.google.com/file/d/1INYHo6JnkKYqLyNVMg2fRVyJKrPShAfa/view?usp=sharing for
# a simple demonstration of how the mesh is generated, and read the comments below to get a deeper understanding
# of how that simple algorithm(defined in gen_peers()) is modified to provide scalability.

# The default parameters are good for network sizes between 15-100 with a good amount of redundancy
# (on average, each node is connected to 5 others) and allows adding up to 85 additional nodes(15+85=100 total)
# before these settings should be modified. There is nothing special about the default value of initial_seed.

# This is a random number which seeds the RNG to ultimately determine the exact network architecture of the finished
# network. It must be the same across all nodes in order for each node to generate the same network.
# Give it some entropy, because (potentially hundreds of) other seeds will be derived from it for large network sizes
# to generate the network
initial_seed = 253358919245475086853614223034892822600
current_seed = initial_seed

# This is the upper bound on your network's scalability. It sets the maximum number of nodes which can be added
# to the network before the network architecture would have to change dramatically to provide them reasonable
# connectivity to each node. Counting how many nodes you want and multiplying that by 2 or 3 seems like a good option :)
# (caveat: the complexity of the network generator is roughly O(n^2) so larger networks will consume more CPU
# resources, don't make this over 300 or so unless you want to crash the Pis :)) Also, if this is too high
# you will have to crank the max_network_c_ext up very high to achieve reasonable connectedness(redundancy)
# which creates a large performance penalty for the network generator.
max_network_size = 100

# Represents an generalized arbitrary sized network as a collection of nodes['1', '2', '3', .... 'N']
# You may assign these generalized hostnames to IP addresses however you wish
# or, if you want, you can just replace this list with a list of IP addresses, then you won't have to change anything,
# but if you do this you need to make the list at least max_network_size items long
max_hosts = [str(x) for x in range(1,max_network_size+1)]

# This controls the maximum connectedness of your scalable mesh network. Use the comment below for network_c_ext
# to pick a reasonable value, multiply it by some number >~2.7 to get a value for this; round to nearest integer
# (The network compressor cannot make a network with a c_ext greater than about 3/8 of the input network c_ext)
# max_network_c_ext = 25
max_network_c_ext = 30  # default: 25


max_network = generate_uncompressed_mesh(max_hosts, max_network_c_ext)

# This controls the connectedness of your network. It represents how many other nodes each node connects to it to form
# the output mesh. If c_ext = network_size-1 then the network is "fully complete" meaning all nodes are connected to
# all other nodes. This is the most redundant option, but it is very inefficient and it buts a significant burden
# on your networking equipment which would have to handle (N^2)-N simultaneous connections where N = network size.
# (that's 2550 connections for N=51!)
# The ratio of c_ext to network size roughly determines (on average) the number of nodes which would have to go down
# before packet delivery to the remaining nodes is impacted. For example, for N=20 and c_ext=5, on average
# 25% of the nodes(5 of them) would have to go down before packet delivery between the
# remaining 15 was significantly impaired. Recommended value is in the 3-10 range for networks under 150 nodes.
# If this value is too low, the network may be unsolvable
# (some nodes will be completely isolated from the rest of the network) so keep this above 3-ish to avoid this
network_c_ext = 3  # default: 5

# The network compressor turns the maximum size (max_network_size) network into a smaller one which can be
# incrementally scaled up to max_network_size by increasing network_size without significantly altering the
# network architecture. As a side effect of reducing the network size, the ratio of equivalent c_ext to network
# size increase significantly, so the scale_down_network_connectedness() algorithm is used to reduce the equivalent
# c_ext to some sane arbitrary value specified by network_c_ext. (An N=100 c_ext = 20 network is pretty connected
# already, a compressed N=30 c_ext=18-ish network is pushing the limits of practicality a bit...) scale_down_network_
# connectedness() is lossy and has a hard time reducing the c_ext to values higher than about 3/8 of the input network
# c_ext, hence why max_c_ext should be >~2.7x larger than the target one.

# This is the actual size of your network. If it is significantly smaller than max_network_size, then
# your network can be incrementally increased or decreased(scaled) without significantly impacting the network
# architecture by modifying this value. (Yay scalability!)
network_size = 10  # default: 51
hosts = max_hosts[:network_size]  # max_network_size > network_size so len(max_hosts) > len(hosts)

network = compress_network(max_network, network_size, network_c_ext)
pretty_print(network)
print(classify_network(network))

print("broadcast ttl from node 1: " + str(get_broadcast_ttl(network, hosts, '1', verbose=False)))