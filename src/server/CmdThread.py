import socket
import struct
import threading
# Remote_tuple = ([socket1, socket2],[address1, address2]) etc.
class CommandThread(threading.Thread):
    def takeinput(self, command):
        import os
        print("executing: "+command)
        os.system(command)
        return

    def start(self, command):
        threading.Thread(target=self.takeinput, args=(command,), name='CmdThread').start()
        return