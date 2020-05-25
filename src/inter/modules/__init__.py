import os
import sys
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.append(this_dir)
print(this_dir)
import config_client
import discover
import echo
import example
import exec
import finder
import primitives
import sharepeers
import vote