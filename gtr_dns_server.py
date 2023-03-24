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
hostnames = [ 
	{
		'name': resolver_finder_hostname,
		'address': '127.0.0.5',
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
		D: [A(IP), AAAA((0,) * 16), soa_record] + ns_records,
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
	qn = str(qname)
	qtype = request.q.qtype
	qt = QTYPE[qtype]

	for hostname in hostnames:
		if qn == hostname['D'] or qn.endswith('.' + hostname['D']):
	
			for name, rrs in hostname['records'].items():
				if name == qn:
					for rdata in rrs:
						rqt = rdata.__class__.__name__
						if qt in ['*', rqt]:
							if qname == resolver_finder_hostname:
								rdata = A(client_address)
							reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
	
			for rdata in hostname['ns_records']:
				reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=hostname['TTL'], rdata=rdata))
	
			reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=hostname['TTL'], rdata=soa_record))
	
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


def main():
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
	parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
	parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
	parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
	parser.add_argument('--interface', default='eth0', help='Ethernet interface to listen on.')
	
	args = parser.parse_args()
	if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

	print("Starting nameserver...")

	"""Get IP address to bind to"""
	if args.interface in ni.interfaces():
		ipv4_address = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
		ipv6_address = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr'].split('%')[0]

	servers = []
	for ip_address in [ipv4_address]: #, ipv6_address]:
		print('%s, udp' % ip_address)
		if args.udp: servers.append(socketserver.ThreadingUDPServer((ip_address, args.port), UDPRequestHandler))
		print('%s, tcp' % ip_address)
		if args.tcp: servers.append(socketserver.ThreadingTCPServer((ip_address, args.port), TCPRequestHandler))

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
