# Python 3.6.2
# Script automating the starting of the client individually.

import server
port = 3705

x = server.Server()
x.initialize(port=port, method="socket", listening=True, network_injection=True)