import random
initial_seed = 3847832947
current_seed = initial_seed
our_IP = "192.168.53.33"
network_c_ext = 2
hosts = [item.strip('\n') for item in open("hosts.bin", "r").readlines()]


def reseed():
    # Generate a deterministic sequence of RNG seeds from one initial seed and apply it
    global current_seed
    random.seed(current_seed)
    current_seed = random.randint(0,9999999999)


def gen_peers(network_tree, node, c_ext):
    reseed()
    remote_hosts = list(hosts)  # make a copy of this that we can mutilate

    remote_hosts.remove(node)

    peers = []
    for i in range(0, c_ext):
        selected_peer = random.choice(remote_hosts)
        print('Selected peer: '+selected_peer + " with seed: "+str(current_seed) + " for "+node)
        peers_peers = network_tree[selected_peer]

        # When we connect to a node, add ourselves to their peers list
        if node not in peers_peers:
            peers_peers.append(node)
        network_tree.update({selected_peer: peers_peers})

        peers.append(selected_peer)
        remote_hosts.remove(selected_peer)
        reseed()

    network_tree.update({node: peers})
    return network_tree


def gen_network(network, c_ext):
    network_tree = {}

    for host in hosts:
        network_tree.update({host: []})

    for node in network:
        network_tree = gen_peers(network_tree, node, c_ext)

    return network_tree


print(gen_network(hosts, 2))
