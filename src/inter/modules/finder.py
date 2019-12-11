import os
import sys

# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../../client/')
sys.path.insert(0, '../../../server/')
sys.path.insert(0, (os.path.abspath('../../inter/misc')))
import primitives
import client
import readPartNumbers

os.chdir(os.path.abspath('../../client/'))
print(os.getcwd())


def led_on(shelf_num):
    pass
    # interface led
    # RPI GPIO module


def respond_start(message, sub_node, log_level, part_number_list):
    _primitives = primitives.Primitives(sub_node, log_level)
    arguments = _primitives.parse_cmd(message)

    print(arguments)
    part_number = arguments[0]
    print(part_number)
    """  local_ip = _primitives.get_local_ip()
    our_parts = readPartNumbers.find_my_parts(local_ip)
    for item in our_parts:
        part_number_list.append(item[0])
        print(item[0])"""
    if part_number in part_number_list:
        print("We found it")

    """Called by the client's listener_thread when it received a [name]: flag"""

    # find shelf for item num
    return part_number
