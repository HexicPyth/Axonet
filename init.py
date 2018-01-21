# Xnet - init.py Written by HexicPyth/Xenonymous
# Start two processes, a server and a client, each with one sub-thread,
# who can communicate with each other through raw socket servers.

import multiprocessing
from time import sleep
import server
import client
actions = ['server.py', 'client.py']


def worker(action):  # Worker function
    print('action:', action)
    if action == 'server.py':
        from server import init
        print("Initializing server...")
        init()
        print('Server has been successfully initialized')
    elif action == 'client.py':
        from client import init
        print("Initializing client...")
        init()
        print('Client has been successfully initialized')


if __name__ == '__main__':
    jobs = []
    for i in range(0, 2):
        p = multiprocessing.Process(target=worker(actions[i]))
        jobs.append(p)
        p.start()
        sleep(1)
