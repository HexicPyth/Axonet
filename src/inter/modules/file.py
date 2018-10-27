# file:(64-bit file hash):(32-bit file length):(128-bit origin address identifier)
import os
import sys
import hashlib
# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../client/')
sys.path.insert(0, '../../server/')
no_prop = "ffffffffffffffff"
file_path = []
current_file_sectors = []
current_file_size = len(current_file_sectors)
x = 0
# The following md5sum function was adapted liberally from
# "prologic" at BitBucket
# https://bitbucket.org/prologic/tools/
# https://bitbucket.org/prologic/
# Accessed 06/28/18 00:00 UTC


def sift_data(data, n):
    """"Split a lot of data into chunks of size n"""
    segments = [data[i:i+n] for i in range(0, len(data), n)]
    return segments


def read_from_file(file_path, n=500000):
    """Read lots of bytes from a file and return a list of bytes, in chunks('sectors') of size n"""
    path = os.path.abspath(file_path)
    data = open(path, "rb").read()

    bin_data = data.hex()
    sectors = sift_data(bin_data, n)
    return sectors


def md5sum(filename):
    global file_path
    hash_function = hashlib.md5()
    file_path = os.path.abspath(filename)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(128 * hash_function.block_size), b""):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def initiate(net_tuple, arguments):
    """ Called from the network injector when it receives a $file: flag"""
    import inject
    injector = inject.NetworkInjector()
    file_path = arguments[0]

    if os.path.isfile(os.path.abspath(file_path)):

        abs_path = os.path.abspath(file_path)
        file_size = os.path.getsize(abs_path)

        # Hand control to localhost client
        localhost_socket = injector.lookup_socket("127.0.0.1", net_tuple)
        if localhost_socket != 1:
            localhost_connection = (localhost_socket, "127.0.0.1")
            init_msg = no_prop+":init_file:"+abs_path+":"+str(file_size)
            injector.send(localhost_connection, init_msg, sign=False)
        pass


def respond_start(proxy_addr, checksum, file_list, network_tuple, init=True):
    """Called by the client's listener_thread when it received a file: flag"""

    global x
    global current_file_sectors
    global current_file_size

    import primitives
    import inject
    import client

    primitives = primitives.Primitives("Debug", "Client")
    Injector = inject.NetworkInjector()
    Client = client.Client()

    print("Initiating data transfer to proxy...")
    print("Proxy Address: "+proxy_addr)
    print("Checksum: "+checksum)

    path_to_file = str(file_path)
    if init:
        current_file_sectors = read_from_file(path_to_file)
        current_file_size = len(current_file_sectors)

        x += 1
        print("Counter: "+str(x))

    elif not init:
        print(type(current_file_sectors))
        current_file_sectors.pop(0)
        x += 1
        print("Counter: "+str(x))
        print("Transfering sector: "+str(len(current_file_sectors)) + " of "+str(current_file_size))
        print(len(current_file_sectors))

    try:
        sector = current_file_sectors[0]
        print()
        print(sector[:16])
        print()

        file_tuple = primitives.find_file_tuple(file_list, checksum)
        file_size = file_tuple[0]
        proxy_addr = file_tuple[3]
        proxy_socket = Client.lookup_socket(proxy_addr, network_tuple)
        proxy_connection = (proxy_socket, proxy_addr)

        # Format: proxy:file:checksum:file_size:proxy_address:data
        data = sector
        data_packet = ':'.join([no_prop, "proxy", "file", checksum, str(file_tuple[0]), proxy_addr, data])
        print("Data packet made")
        Client.send(proxy_connection, data_packet, sign=False)
        print("Sent")
    except IndexError:
        print("File Transfer complete!")

def start(stage, proxy, checksum, localhost, file_list, network_tuple):
    import primitives
    import client
    Primitives = primitives.Primitives("Debug", "Client")
    Client = client.Client()

    """Called at then end of elect: when the election for dfs-[...] completes"""
    # file:(64-bit file hash):(32-bit file length):(128-bit origin address identifier)

    if stage == 1:
        print("Proxy: " + proxy)
        print("File: "+str(file_path))
        file_tuple = Primitives.find_file_tuple(file_list, checksum)

        if proxy == Primitives.get_local_ip():
            proxy_socket = localhost
            proxy_address = "127.0.0.1"
        else:
            proxy_socket = Client.lookup_socket(proxy, ext_net_tuple=network_tuple)
            proxy_address = proxy

        proxy_connection = (proxy_socket, proxy_address)

        print("Client -> Info: Passing control to proxy")
        proxy_msg = no_prop + ":proxy:init_file_dist:" + checksum + ":" + file_tuple[0] + ":" + str(proxy_address)
        Client.send(proxy_connection, proxy_msg, sign=False)
