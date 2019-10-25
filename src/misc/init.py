import multiprocessing
import threading
import sys
from time import sleep
import os

# Some import "magic" to import from other directories; (see issue #1)
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../server/')
sys.path.insert(0, '../client')  # TODO: Directory restructure; We shouldn't have to modify PYTHON_PATH


actions = ['server.py', 'client.py']
PORT = 3705
network_architecture = "complete"


def worker(action):  # Worker function
    import init_server
    import init_client
    global network_architecture

    print('action:', action)
    if action == 'server.py':
        print("Initializing server...")
        # Apparently multiprocessing doesn't like starting things that include while loops in the main process,
        # so instead, we'll start the server in a thread (of a child process of a process)
        thread = threading.Thread(target=init_server.init, args=(network_architecture,))
        thread.start()
        print('Server has been successfully initialized')

    elif action == 'client.py':
        print("Initializing client...")
        thread = threading.Thread(target=init_client.init, args=(network_architecture,))
        thread.start()
        print('Client has been successfully initialized')


if __name__ == '__main__':
    jobs = []
    for i in range(0, 2):
        p = multiprocessing.Process(target=worker(actions[i]))
        jobs.append(p)
        p.start()
        sleep(1)
