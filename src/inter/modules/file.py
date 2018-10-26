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

# The following md5sum function was adapted liberally from
# "prologic" at BitBucket
# https://bitbucket.org/prologic/tools/
# https://bitbucket.org/prologic/
# Accessed 06/28/18 00:00 UTC


def sift_data(data, n):
    """"Split a lot of data into chunks of size n"""
    segments = [data[i:i+n] for i in range(0, len(data), n)]
    return segments


def read_from_file(file_path, n=512000):
    """Read lots of bytes from a file and return a list of bytes, in chunks('sectors') of size n"""
    path = os.path.abspath(file_path)
    data = open(path, "rb").read()

    bin_data = data.hex()
    sectors = sift_data(bin_data, n)


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


def respond_start(proxy_addr, file_path, checksum, network_tuple):
    """Called by the client's listener_thread when it received a file: flag"""
    import inject
    injector = inject.NetworkInjector()
    msg = str(proxy_addr)+str(file_path)+str(checksum)
    injector.broadcast(injector.prepare(msg), network_tuple)


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
        proxy_msg = no_prop + ":proxy:init_file:" + checksum + ":" + file_tuple[0] + ":" + "YOUR_ADDR"
        Client.send(proxy_connection, proxy_msg, sign=False)
