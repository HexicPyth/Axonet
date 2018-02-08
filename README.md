# Axonet

Axonet is an active <b>proof of concept</b> demonstrating the functionality, special attributes, and applications of decentralized networking/computing on computationally expensive problems and distributed tasks. <b> The cluster(s) consist of any networked devices on your local subnet.</b> For nodes, I recommend using as many old and/or not-otherwise-useful laptops as you can come up with, because they're easy to find, and power efficent when on smart chargers. However that's up to you.

## Getting Started

  <b>Setting up an environment:</b> 
  - switch to some convenient directory like `~/` and:
  - `mkdir Axonet`
  - `cd Axonet`
  - `git clone https://github.com/HexicPyth/Axonet.git ./`
  
  <b>Bootstrapping the network</b>
  - Prepare & launch node #1: 
    - `python3.6 src/server/init_server.py`
    - modify src/client/init_client.py so that remote_addresses=None
    - `python3.6 src/client/init_client.py`
  - Boostrap the network with node #2
    - `python3.6 src/server/init_server.py`
    - modify src/client/init_client.py so that remote_addresses=["Local_IP_ADDRESS_OF_NODE#1"] substituding the local ip address of node #1 respectively.
    - `python3.6 src/client/init_client.py`
    
  <b>Adding more devices to the network (node# > 2)</b>
 - `python3.6 src/server/init_server.py`
  - modify src/client/init_client.py so that remote_addresses = (an array of at least one local IP address of any other node on the network) The network will take care of completing itself, so don't hesitate to only assign one address here.
  i.e remote_addresses=["192.168.1.91"] or remote_addresses=["192.168.1.91","192.168.1.12"], etc.
  - `python3.6 src/client/init_client.py`
  
      

### Prerequisites


```A Unix-based operating system: Preferably linux``` - That's your decision to make, not mine. Install as applicable to your hardware? :P

```Python 3.6+``` - Install as applicable to your operating system.


### Installing

<b> See 'Getting Started' </b>

## Authors

* **HexicPyth** - *Research, Design, and Development*

See also the list of [contributors](https://github.com/hexicpyth/Axonet/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## README TODO:
- Discuss network injection and flags
