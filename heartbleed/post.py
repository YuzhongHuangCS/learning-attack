#!/bin/python3
import string
import random
import http.client
import urllib.parse

def randomString(length):
	maxlength = len(string.ascii_letters + string.digits)
	if(length > maxlength):
		return ''.join(random.sample(string.ascii_letters + string.digits, maxlength)) + randomString(length - maxlength)
	else:
		return ''.join(random.sample(string.ascii_letters + string.digits, length))

conn = http.client.HTTPSConnection('218.244.141.205', check_hostname=None)

for i in range(500):
	body = urllib.parse.urlencode({'username': randomString(10), 'password': randomString(10)})
	conn.request('POST', '/', body)
	conn.getresponse().read()
