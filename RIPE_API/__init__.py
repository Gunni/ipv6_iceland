# -*- coding: utf-8 -*-
import requests
import json
import ipaddress

class RIPEAPIException(Exception):
	pass

def call_ripe_api(what):
	r = requests.get(what, headers={'Accept': 'application/json'})
	status = r.status_code

	if status == 400:
		print('The service is unable to understand and process the request')
	elif status == 403:
		print('Query limit exceeded')
	elif status == 404:
		#print('No results were found (on a search request), or object specified in URI does not exist')
		return []
	elif status == 409:
		print('Integrity constraint was violated (e.g. when creating, object already exists)')
	elif status == 500:
		print('Query limit exceeded')

	if r.status_code != 200:
		raise RIPEAPIException('Unexpected error from RIPE Rest API: {} {}'.format(status, what))

	return json.loads(r.text)['objects']['object']


def get_as_from_asset(asset):
	r = []
	asset = call_ripe_api('https://rest.db.ripe.net/ripe/as-set/{}'.format(asset))

	if len(asset) == 0:
		return []

	for obj in asset:
		attrs = obj['attributes']['attribute']
		for attr in attrs:
			if 'link' not in attr:
				continue
			if attr['name'] != 'members':
				continue

			if attr['referenced-type'] == 'as-set':
				r += get_as_from_asset(attr['value'])  # recursive call, dangerous?
			elif attr['referenced-type'] == 'aut-num':
				r.append(attr['value'])

	return r


def get_nets_from_asn(asn):
	r = []
	routes = call_ripe_api('https://rest.db.ripe.net/search?source=ripe&type-filter=route,route6&inverse-attribute=origin&query-string={}'.format(asn))

	if len(routes) == 0:
		return []

	for route in routes:
		attrs = route['attributes']['attribute']
		o = {}
		for attr in attrs:
			if attr['name'] == 'origin':
				o['origin'] = attr['value'].upper()
			elif attr['name'] == 'route':
				o['type'] = 'ipv4'
			elif attr['name'] == 'route6':
				o['type'] = 'ipv6'

			if attr['name'] == 'route' or attr['name'] == 'route6':
				o['cidr'] = attr['value'].lower()

		if 'origin' in o.keys() and 'type' in o.keys() and 'cidr' in o.keys():
			o['asn'] = asn
			r.append(o)

	return r


def get_subnets_from_asset(asset):
	r = []
	for aut_num in get_as_from_asset(asset):
		prefixes = get_nets_from_asn(aut_num)
		for prefix in prefixes:
			r += [prefix]

	r_sorted_ip_asn = sorted(
		r,
		key=lambda k: (
			int(k['asn'][2:]),  # sort by ASn next
			ipaddress.get_mixed_type_key(ipaddress.ip_network(k['cidr']))  # sort by ip first
		)
	)  # maybe too slow?

	return r_sorted_ip_asn

