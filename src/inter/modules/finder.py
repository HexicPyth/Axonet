import os
import sys
import time


# Allow us to import the client
this_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(this_dir)
sys.path.insert(0, '../../../client/')
sys.path.insert(0, '../../../server/')
sys.path.insert(0, (os.path.abspath('../../inter/misc')))
try:
    import board
    import busio
    from adafruit_ht16k33 import segments
except ImportError:
    print("Not a raspberry so cant import board")

import primitives
import client
import readPartNumbers

os.chdir(os.path.abspath('../../client/'))


def respond_start(message, sub_node, log_level, line_number_list):
    _primitives = primitives.Primitives(sub_node, log_level)
    arguments = _primitives.parse_cmd(message)

    print(arguments)
    line_number = arguments[0]
    print(line_number)

    if line_number in line_number_list:
        print("We found it")
        # If the last four bytes of our IP

    """Called by the client's listener_thread when it received a [name]: flag"""

    # find shelf for item num
    return line_number


def display_token(token):
    # Create the I2C interface.
    i2c = busio.I2C(board.SCL, board.SDA)

    # Create the LED segment class.
    # This creates a 7 segment 4 character display:
    display = segments.Seg7x4(i2c)

    # Clear the display.
    display.fill(0)

    display.print(token)
