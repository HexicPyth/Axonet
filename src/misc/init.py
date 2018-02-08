import multiprocessing
import threading
import sys
from time import sleep
# Some import "magic" to import from other directories; (see issue #1)
sys.path.insert(0, '../server/')
sys.path.insert(0, '../client')

import init_client
import init_server



actions = ['server.py', 'client.py']
PORT = 3705


def worker(action):  # Worker function
    print('action:', action)
    if action == 'server.py':
        print("Initializing server...")
        # Apparently multiprocessing doesn't like starting things that include while loops in the main process,
        # so instead, we'll start the server in a thread (of a child process of a process)
        thread = threading.Thread(target=init_server.init)
        thread.start()
        print('Server has been successfully initialized')

    elif action == 'client.py':
        print("Initializing client...")
        thread = threading.Thread(target=init_client.init)
        thread.start()
        print('Client has been successfully initialized')


if __name__ == '__main__':
    jobs = []
    for i in range(0, 2):
        p = multiprocessing.Process(target=worker(actions[i]))
        jobs.append(p)
        p.start()
        sleep(1)