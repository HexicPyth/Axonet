import os
import sys

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../../client/')
sys.path.insert(0, '../../../server/')

def initiate(net_tuple, arguments):
    """ Called from the network injector when it receives a $[name]: flag"""

    pass  # Code goes here


def respond_start():
    """Called by the client's listener_thread when it received a [name]: flag"""
    pass  # Code goes here


def start():
    """(Optional) Called at then end of sync: to allow for
     module-specific I/O in modules that need access to the disk"""

    pass  # (not used)
