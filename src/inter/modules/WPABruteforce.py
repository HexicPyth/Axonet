# file:(64-bit file hash):(32-bit file length):(128-bit origin address identifier)
import os
import sys
import secrets

# Allow us to import the client
original_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(original_path)
sys.path.insert(0, '../../client/')
sys.path.insert(0, '../../server/')
no_prop = "ffffffffffffffff"
dict_size = 0


def initiate(net_tuple, arguments):
    global dict_size
    """ Called from the network injector when it receives a $WPABruteForce: flag"""
    # WPABruteForce:dictionary size

    import inject
    injector = inject.NetworkInjector()
    dict_size = arguments[0]

    # 1. Benchmark each node and distribute results linearly

    # 1a. Create a new page to work with
    benchmark_id = secrets.token_hex(8)
    newpage_msg = "newpage:"+benchmark_id
    injector.broadcast(newpage_msg, net_tuple)

    # 1b. Initiate a benchmark
    benchmark_msg = "benchmark:WPA:"+benchmark_id
    injector.broadcast(benchmark_msg, net_tuple)


def do_wpa_benchmark():
    os.chdir(original_path)
    os.chdir(os.path.abspath("./scripts/WPABenchmark"))

    try:
        os.remove(os.path.abspath("./out.txt"))
    except FileNotFoundError:
        pass

    os.system("sh dobenchmark.sh")
    benchmark_lines = open("out.txt").readlines()
    result = benchmark_lines[-1]
    score = result[:-5]
    return int(score)


def respond_start(score, page_id, addr_id, net_tuple):
    """Called by the client's listener_thread when it finished executing self.do_wpa_benchmark"""
    import client
    import inject
    Client = client.Client()
    Injector = inject.NetworkInjector()
    print("WPABruteForce -> respond_start: Result: "+str(score))
    print("WPABruteForce -> respond_start: Writing score to page: "+page_id)

    Client.write_to_page(page_id, str(score))
    pageline = addr_id+":"+str(score)

    # 2. Synchronise pagefiles
    Injector.broadcast("sync"+":"+page_id+":"+pageline, net_tuple)


def start(page_id, raw_lines):
    global dict_size
    """Called from sync: once all nodes have contributed to the network"""
    print("\nWPABruteForce -> Pretending to do calculations...")
    print("WPABruteForce -> Working in page: "+page_id)
    print("WPABruteForce ->Raw lines: "+str(raw_lines))
    score_list = [parse_line[33:].rstrip("\n") for parse_line
                  in raw_lines if parse_line != "\n"]
    print("WPABruteForce -> Scores: "+str(score_list))
    print("WPABruteForce -> Dictionary Size: "+str(dict_size))
