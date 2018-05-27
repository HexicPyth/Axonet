import os
import sys
import codecs

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../client/')
sys.path.insert(0, '../../server/')
no_prop = "ffffffffffffffff"
import multiprocessing



def initiate(in_cmd, net_tuple):
    import inject
    injector = inject.NetworkInjector()

    if in_cmd == "corecount":
        print("Injector -> info: Initiating a core count")
        id_length = 16

        # Get a random 64-bit id for this operation
        op_id = codecs.encode(os.urandom(int(id_length / 2)), 'hex').decode()

        injector.broadcast("newpage:" + op_id, net_tuple)
        injector.broadcast(":corecount:" + op_id, net_tuple)

        localhost_socket = injector.lookup_socket("127.0.0.1", net_tuple)
        localhost_connection = (localhost_socket, "127.0.0.1")
        retrieve_msg = "retrieve:" + op_id
        injector.send(localhost_connection, retrieve_msg, sign=True)


def respond_start(page_ids, message):
    import client
    Client = client.Client()

    page_id = message[10:]
    if page_id not in page_ids:
        print(page_id)
        num_of_cores = str(multiprocessing.cpu_count())
        Client.write_to_page(page_id, num_of_cores)
    elif page_id in page_ids:
        pass


def start(page_id, raw_lines, newlines):
    import client
    Client = client.Client()
    print(page_id)
    # corecount stuff.
    almost_formatted_cores = [parse_line[17:].rstrip("\n") for parse_line
                              in raw_lines if parse_line != "\n"]

    formatted_cores = []

    for core_string in almost_formatted_cores:
        try:
            core_int = int(core_string)
            formatted_cores.append(core_int)

        except ValueError:
            pass

    cores = sum(formatted_cores)

    # e.x: #cores: 8
    corecount_string = str("##cores:" + str(cores))

    Client.write_to_page(page_id, corecount_string, signing=False)
    print(formatted_cores)
    print("\nCorecount complete. Available CPU Cores: "+str(cores)+"\n")
