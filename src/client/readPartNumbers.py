import csv
import sys
import os
import urllib.request
import urllib.error
sys.path.insert(0, (os.path.abspath('../misc')))

import primitives
import os

_primitives = primitives.Primitives("Client", "Debug")

def download_racks_csv(url):
    response = urllib.request.urlopen(url)
    data = response.read()  # a `bytes` object
    text = data.decode('utf-8')  # a `str`; this step can't be used if data is binary
    racks_file = open("Racks.csv", "w")
    racks_file.write(text)


def find_my_parts(local_ip, directory_server, path_to_client=None):
    """Given a nodes static IP, find all part numbers assigned to it in the master spreadsheet
        Returns list [(part number, part name, line #), ..., (part number n, part name n, line # n)]"""
    if path_to_client:
        try:
            os.chdir(path_to_client)
        except FileNotFoundError:
            print("Directory does't exist: "+str(path_to_client))
            return
          
    our_parts = []

    ip_bytes = local_ip.split('.')
    ip_byte_four = ip_bytes[4 - 1]

    _primitives.log("Fetching part numbers for " + local_ip + "...", in_log_level="Debug")

    try:
        racks_csv_text = _primitives.download_file(directory_server)

        if racks_csv_text != 1:
            print(os.getcwd())
            open("Racks.csv", "r+").write(racks_csv_text)
            part_number_assignments = open("Racks.csv")
        else:
            raise urllib.error.URLError("Could not access Racks.csv. Directory server offline?")

    except urllib.error.URLError:
        print("ERROR: No internet connection detected; cannot download Racks file... Searching for local copy...")

        try:
            part_number_assignments = open("Racks.csv")
            print("Local Racks.csv found! Proceeding...")

        except FileNotFoundError:
            print("ERROR: No local Racks file found; cannot proceed; returning no parts")
            return []

    csv_reader = csv.reader(part_number_assignments, delimiter=',')
    for row in csv_reader:
        if ip_byte_four in row[3]:
            our_parts.append((row[0], row[1], row[4]))

    _primitives.log("Found "+str(len(our_parts)) + " parts assigned to "+local_ip+"...", in_log_level='Debug')

    return our_parts


if __name__ == "__main__":
    print(find_my_parts(_primitives.get_local_ip())
