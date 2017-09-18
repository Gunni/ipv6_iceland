# 1. Get rix participants
import requests
import json
import RIPE_API as ripe
import ipaddress
from termcolor import colored

def err(msg, code=1):
	print(msg)
	exit(code)

r_participants = requests.get('http://rix.is/participants.json')
if r_participants.status_code != 200:
	err('RIX participants failed to download with status code: {}'.format(r_participants.status_code))

rix = json.loads(r_participants.text)

rix_asns = {m['asnum']: m for m in rix['member_list']}

def get_icelandic_nets():
	r = []
	for asn in rix_asns:
		nets = ripe.get_nets_from_asn('AS{}'.format(asn))

		for net in nets:
			r += [net]

	r_sorted_ip_asn = sorted(
		r,
		key=lambda k: (
			int(k['asn'][2:]),  # sort by ASn next
			ipaddress.get_mixed_type_key(ipaddress.ip_network(k['cidr']))  # sort by ip first
		)
	)  # maybe too slow?

	return r_sorted_ip_asn

v = get_icelandic_nets()

asn_nets = {}
for net in v:
	origin = int(net['origin'][2:])
	if origin not in asn_nets:
		asn_nets[origin] = {}

	ipvX = net['type']
	if ipvX not in asn_nets[origin]:
		asn_nets[origin][ipvX] = []

	asn_nets[origin][ipvX].append(net)

for asn, ipvX in asn_nets.items():
	print('{} AS{}'.format(rix_asns[int(asn)]['name'], asn))

	print('\t{}'.format(net['cidr']))

	if 'ipv6' not in ipvX:
		print('\t{}'.format(colored('NO IPv6 Networks!', 'red', attrs = ['bold'])))
