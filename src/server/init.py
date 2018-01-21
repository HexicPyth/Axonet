import server
x = server.Server()
x.initialize(port=3705, method="socket", listening=True, network_injection=True)
