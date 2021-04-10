import socket
import struct
import datetime
import sys
import os
import secrets
from hashlib import sha3_224

sys.path.insert(0, (os.path.abspath('../misc')))
sys.path.insert(0, (os.path.abspath('../inter/modules')))

import primitives

Primitives = primitives.Primitives("Injector", "Debug")

print("Connecting to localhost...")
# Connect to localhost
_socket = socket.socket()
_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def prepare(message):
    """ Assign unique hashes to messages ready for transport.
        Returns (new hashed message) -> str """

    # Sign the message
    timestamp = str(datetime.datetime.utcnow())
    hash_input = timestamp + message
    sig = sha3_224(hash_input.encode()).hexdigest()[:16]

    out = sig + ":" + message

    # Prepend message length
    out = out.encode('utf-8')
    out_with_padding = struct.pack(">I", len(out)) + out
    print(out)
    out = bytearray(out_with_padding)

    out = bytes(out)
    print(out)
    return out


def send_to_localhost(message):
    print("Sending: "+message)
    _socket.sendall(prepare(message))


def run(msg="", ip=""):

    if ip != "":

        try:
            _socket.connect((ip, 3705))

        except socket.gaierror:
            print("Error: Could not connect to remote host; terminating...")
            quit()

    else:
        _socket.connect(("127.0.0.1", 3705))

    if msg == "":
        msg = input("Enter message here")

    if not msg.startswith("$"):

        try:
            send_to_localhost(msg)

        except (BrokenPipeError, OSError):
            print("An error occurred sending to localhost; Quietly dying...")
            quit()

    if msg == "stop":
        send_to_localhost(msg)
        quit()

    else:
        # Unnecessary shit for complicated network operations
        if msg.startswith("$vote:"):
            args = Primitives.parse_cmd(msg)
            reason = args[0]

            localhost_message = "vote:" + reason
            send_to_localhost(localhost_message)

        if msg == "$discover":
            print("Starting peer discovery")

            op_id = secrets.token_hex(8)
            send_to_localhost("vote:discovery-"+op_id)

    _socket.shutdown(0)
    _socket.close()


if __name__ == '__main__':
    argv = sys.argv[1:]
    if len(argv) > 2:
        print("Error: SimpleInjector takes two arguments; Terminating...")
        quit()

    if len(argv) == 2:
        run(ip=argv[0], msg=argv[1])

    else:
        run()  # No arguments were provided; we will take input via stdin and send to localhost
