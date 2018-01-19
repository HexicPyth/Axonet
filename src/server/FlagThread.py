import struct
import multiprocessing
import sys
import os
import hashlib
import datetime

DEBUG_MODE = True
global proc  # Pointer to this process
# Remote_tuple = ([socket1, socket2],[address1, address2]) etc.

'''
 *cough* 
 SOCKETS THAT DON'T HAVE A REMOTE ADDRESS/PORT DON'T DESCRIBE A CONNECTION BETWEEN TWO NODES 
 ON A NETWORK AND THEREFORE AREN'T SOCKETS!      *cough* excuse me
'''


class FlagThread(multiprocessing.Process):

    def send(self, _sock, msg, addr, sockets, addresses):

        dateandtime = str(datetime.datetime.now())
        hash_msg = hashlib.sha3_512((msg + dateandtime).encode()).hexdigest()[:15]  # Hash our message
        msg = hash_msg + ">" + msg
        print("Client -> Sending ",msg,sep='')
        msg = msg.encode('utf-8')  # Are input is not encoded; do so now.

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg

        # If DEBUG_MODE is not active
        if not DEBUG_MODE:
            try:
                _sock.sendall(msg)
            except BrokenPipeError:
                print("FlagThread - send() : Error: Something has gone really catastrophically wrong... "
                      "(BrokenPipeError)")
                print("FlagThread - send() : Cannot send message: "+str(msg))
                pass
        else:
            print("FlagThread - send() : Attempting to send message")
            print("FlagThread - send() : Socket: ", str(_sock), sep='')
            print("FlagThread - send() : ...")

            if not DEBUG_MODE:
                try:
                    _sock.sendall(msg)
                except BrokenPipeError:
                    print("FlagThread - send() : BrokenPipeError. Socket:", str(_sock), sep='')
            else:
                try:
                    _sock.sendall(msg)
                except BrokenPipeError:
                    print("Eww Awful bugs bite :( *cough* *cough*")
                    print("Failed to send message to",addr)
                    index = addresses.index(addr)
                    print(" -- Socket in question:", sockets[index])
                    print("\nTODO: Fix this awful infection bug\n")

    def Broadcast(self, flag, sockets, addresses):
        if flag != "none":

            net_index = 0  # Use this counter to keep track of our index in addrs[n] and sockets[n]

            for i in sockets:
                # Recursively send('Broadcast') the given flag to every machine in remote_addresses
                print("FlagThread - Broadcast() : Sending: ", flag, "' to: "+addresses[net_index] + "using socket: ", str(i), sep='')
                self.send(i, flag, addresses[net_index], sockets, addresses)
                net_index += 1

            return  # go to takeinput(...)
        else:

            print("FlagThread - Broadcast() : refreshing...")
            return  # goto takeinput(...)

    def takeinput(self, fileno, sockets, addresses):
        print("FlagThread - takeinput() : Sockets: ", str(sockets), sep='')
        print("FlagThread - takeinput() : Adresses: ", str(addresses), sep='')

        remote_tuple = ((sockets, addresses))
        sys.stdin = os.fdopen(fileno)  # Re-open stdin so we can take input from a multiprocess

        while 1:
            cmd = str(input("\nFlagThread - takeinput() : Enter the flag you wich to inject into the network(or enter"
                            " \"none\" to refresh): \n"))

            self.Broadcast(cmd, sockets, addresses)

    def start(self, clients, addresses):
        print("FlagThread - start() : Starting FlagThread with the following:")
        print(" -- Addresses: ", addresses, sep='')
        print(" -- Sockets: ", clients, sep='')


        fn = sys.stdin.fileno()  # Save our curreant stdin as 'fn' so we can pass it to the multiprocess.
        global proc
        proc = multiprocessing.Process(target=self.takeinput, args=(fn,clients, addresses), name='FlagThread')

        proc.start()  # Start our multiprocess with the current stdin and remote_tuple

    def Terminate(self):
        global proc
        print("FlagThread - Terminate() : Reluctantly terminating myself... * cries to the thought of SIGKILL *")
        proc.terminate()
        return