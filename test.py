#import urllib.request

#url = 'http://73.17.34.121/hosted/hosts.bin'
#response = urllib.request.urlopen(url)
#data = response.read()      # a `bytes` object
#text = data.decode('utf-8') # a `str`; this step can't be used if data is binary
#nodes = [line for line in text.split("\n") if line not in ["\n", "", '']]
#print(nodes)

from src.client import client
