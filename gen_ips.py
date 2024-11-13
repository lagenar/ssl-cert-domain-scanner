import json
import ipaddress
import csv


with open("ips.csv", 'w') as out:
    writer = csv.writer(out)
    ranges = json.load(open('ip-ranges.json'))
    for prefix in ranges['prefixes']:
        if prefix['service'] == 'EC2' and prefix['region'].startswith('us-east-'):
            network = ipaddress.ip_network(prefix['ip_prefix'])
            for ip in network:
                writer.writerow([ip])
