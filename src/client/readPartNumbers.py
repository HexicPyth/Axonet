import csv
import sys
import os
sys.path.insert(0, (os.path.abspath('../misc')))

import primitives
_primitives = primitives.Primitives("Client", "Debug")


def find_my_parts(local_ip):
    """Given a nodes static IP, find all part numbers assigned to it in the master spreadsheet
        Returns list [(part number, part name, line #), ..., (part number n, part name n, line # n)]"""

    our_parts = []

    ip_bytes = local_ip.split('.')
    ip_byte_four = ip_bytes[4 - 1]
    _primitives.log("Fetching part numbers for "+local_ip+"...", in_log_level="Debug")

    with open("Racks.csv") as part_number_assignments:
        csv_reader = csv.reader(part_number_assignments, delimiter=',')
        for row in csv_reader:
            if ip_byte_four in row[3]:
                our_parts.append((row[0], row[1], row[4]))

    _primitives.log("Found "+str(len(our_parts)) + " parts assigned to "+local_ip+"...",
                    in_log_level='Debug')

    return our_parts


print(find_my_parts(_primitives.get_local_ip()))