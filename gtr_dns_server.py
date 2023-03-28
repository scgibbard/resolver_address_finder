#!/usr/bin/env python3
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import netifaces as ni
import socket
import ipaddress

try:
	from dnslib import *
except ImportError:
	print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
	sys.exit(2)


class DomainName(str):
	def __getattr__(self, item):
		return DomainName(item + '.' + self)

"""Make this handle multiple records"""
resolver_finder_hostname = 'resolver-ip-address.globaltraceroute.com.'
resolver_finder_v6_hostname = 'resolver-ipv6-address.globaltraceroute.com.'
hostnames = [ 
	{
		'name': resolver_finder_hostname,
		'address': '127.0.0.5',
		'address6': '1::2',
	},
	{
		'name': resolver_finder_v6_hostname,
		'address': '127.0.0.4',
		'address6': '1::1',
	},
]
name_servers = [
	{
		'name': 'gtr-ns1.globaltraceroute.com.',
		'address': '52.70.90.34',
	},
	{
		'name': 'gtr-ns2.globaltraceroute.com.',
		'address': '72.44.50.212',
	}
]
for hostname in hostnames:
	D = DomainName(hostname['name'])
	hostname['D'] = D
	IP = hostname['address']
	hostname['IP'] = IP
	IP6 = hostname['address6']
	hostname['IP6'] = IP6
	TTL = 60
	hostname['TTL'] = TTL
	
	soa_record = SOA(
		mname=DomainName(name_servers[0]['name']),  # primary name server
		rname=DomainName('support.globaltraceroute.com.'),  # email of the domain administrator
		times=(
			201307231,  # serial number
			60 * 60 * 1,  # refresh
			60 * 60 * 3,  # retry
			60 * 60 * 24,  # expire
			60 * 60 * 1,  # minimum
		)
	)
	hostname['soa_record'] = soa_record
	#ns_records = [NS(DomainName('-ns1.globaltraceroute.com.')), NS(DomainName('gtr-ns2.globaltraceroute.com.'))]
	ns_records = []
	for name_server in name_servers:
		ns_records.append(NS(DomainName(name_server['name'])))
	hostname['ns_records'] = ns_records
	records = {
		D: [A(IP), AAAA(IP6), soa_record] + ns_records,
		#D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
		#D.ns2: [A(IP)],
		#D.mail: [A(IP)],
		#D.andrei: [CNAME(D)],
	}
	hostname['records'] = records


def dns_response(data, client_address):
	request = DNSRecord.parse(data)

	print(request)

	reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

	qname = request.q.qname
	qn = str(qname).lower()
	qtype = request.q.qtype
	qt = QTYPE[qtype]

	got_answer = False
	should_servfail = False
	print(hostnames)
	for hostname in hostnames:
		print('in hostname loop')
		print(qn)
		print(hostname['D'])
		if qn == hostname['D'] or qn.endswith('.' + hostname['D']):
			print('in if')
	
			for name, rrs in hostname['records'].items():
				print('in for')
				if name == qn:
					print('in if name == qn')
					for rdata in rrs:
						print('in rdata for loop')
						rqt = rdata.__class__.__name__
						if qt in ['*', rqt]:
							print('in qt in *')
							print(qn)
							print(resolver_finder_hostname)
							print(resolver_finder_v6_hostname)
							if qn == resolver_finder_hostname:
								print('qn is resolver_finder_hostname')
								if rqt == 'A':
									print('found a record')
									if type(ipaddress.ip_address(client_address)) == ipaddress.IPv4Address:
										rdata = A(client_address)
										got_answer = True
									else: 
										should_servfail = True
										print("Rejecting not V4")
								else: 
									should_servfail = True
									print("Rejecting not V4")
							elif qn == resolver_finder_v6_hostname:
								print('qn is resolver_finder_v6_hostname')
								if rqt == 'AAAA':
									print('found aaaa record')
									if type(ipaddress.ip_address(client_address)) == ipaddress.IPv6Address:
										rdata = AAAA(client_address)
										got_answer = True
									else: 
										should_servfail = True
										print("Rejecting not V6")
								else: 
									should_servfail = True
									print("Rejecting not V6")
							print('at reply.add_answer')
							if not should_servfail:
								reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
							if not should_servfail:
								print('not should_servfail')
								got_answer = True
	
			for rdata in hostname['ns_records']:
				reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=hostname['TTL'], rdata=rdata))
		    
			print('checking got_answer and should_servfail')
			if not got_answer and not should_servfail:
				reply.header.rcode = getattr(RCODE,'NXDOMAIN')
				got_answer = True
			
	if not got_answer:
		print('not got_answer')
		print('replying SERVFAIL')
		reply.header.rcode = getattr(RCODE,'SERVFAIL')
	print("---- Reply:\n", reply)
	
	return reply.pack()



class BaseRequestHandler(socketserver.BaseRequestHandler):

	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
		print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
											   self.client_address[1]))
		try:
			data = self.get_data()
			print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
			self.send_data(dns_response(data, self.client_address[0]))
		except Exception:
			traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

	def get_data(self):
		data = self.request.recv(8192).strip()
		sz = struct.unpack('>H', data[:2])[0]
		if sz < len(data) - 2:
			raise Exception("Wrong size of TCP packet")
		elif sz > len(data) - 2:
			raise Exception("Too big TCP packet")
		return data[2:]

	def send_data(self, data):
		sz = struct.pack('>H', len(data))
		return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

	def get_data(self):
		return self.request[0].strip()

	def send_data(self, data):
		return self.request[1].sendto(data, self.client_address)

class V6ThreadingUDPServer(socketserver.ThreadingUDPServer):
	address_family = socket.AF_INET6
	IPV6_V6ONLY = True

class V6ThreadingTCPServer(socketserver.ThreadingTCPServer):
	address_family = socket.AF_INET6
	IPV6_V6ONLY = True

def main():
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
	parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
	parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
	parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
	parser.add_argument('--interface', default='eth0', help='Ethernet interface to listen on.')
	parser.add_argument('--ipv6', action='store_true', help='Listen on IPv6')
	
	args = parser.parse_args()
	if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

	print("Starting nameserver...")

	"""Get IP address to bind to"""
	if args.interface in ni.interfaces():
		ipv4_address = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
		ipv6_address = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr'].split('%')[0]

	servers = []
	if args.udp: 
		print('%s, udp' % ipv4_address)
		servers.append(socketserver.ThreadingUDPServer((ipv4_address, args.port), UDPRequestHandler))
		if args.ipv6:
			print('%s, udp' % ipv6_address)
			servers.append(V6ThreadingUDPServer((ipv6_address, args.port), UDPRequestHandler))

	if args.tcp: 
		print('%s, tcp' % ipv4_address)
		servers.append(socketserver.ThreadingTCPServer((ipv4_address, args.port), TCPRequestHandler))
		if args.ipv6:
			print('%s, tcp' % ipv6_address)
			servers.append(V6ThreadingTCPServer((ipv6_address, args.port), TCPRequestHandler))

	for s in servers:
		thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
		thread.daemon = True  # exit the server thread when the main thread terminates
		thread.start()
		print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

	try:
		while 1:
			time.sleep(1)
			sys.stderr.flush()
			sys.stdout.flush()

	except KeyboardInterrupt:
		pass
	finally:
		for s in servers:
			s.shutdown()

if __name__ == '__main__':
	main()
