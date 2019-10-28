import os
import sys

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)

sys.path.insert(0, (os.path.abspath('../../client')))
sys.path.insert(0, (os.path.abspath('../../server')))


def initiate(net_tuple, arguments):
    """ Called from the network injector when it receives a $vote:(reason) input"""
    os.chdir(this_dir)
    import inject
    injector = inject.NetworkInjector()
    reason = arguments[0]

    # Start an election
    injector.broadcast("vote:"+reason, net_tuple)


def respond_start():
    """Called by the client's listener_thread when it received a vote: flag"""
    pass  # (not used)

def start():
    """Called at then end of sync: to allow for module-specific I/O in modules that need access to the disk"""
    pass  # (not used)
