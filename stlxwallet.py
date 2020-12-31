# -*- coding: utf-8 -*-
import hashlib
import OpenSSL
from OpenSSL import crypto, SSL
import base64
import base58
import sqlite3
import multiprocessing
from multiprocessing import Process, Manager
import time
import os.path
import os
import requests
import json
import sys
import getpass
import warnings
import random, string

warnings.filterwarnings("ignore", category=FutureWarning)

class bcolors:
	HEADER = ''
	OKBLUE = ''
	SBLUE = ''
	OKGREEN = ''
	WARNING = ''
	FAIL = ''
	ENDC = ''
	BOLD = ''
	UNDERLINE = ''

hash_functions = {
	'md5': hashlib.md5,
	'sha1': hashlib.sha1,
	'sha224': hashlib.sha224,
	'sha256': hashlib.sha256,
	'sha384': hashlib.sha384,
	'sha512': hashlib.sha512
}

HASH_TYPE = 'sha256'
sys.tracebacklimit = 0

def randomword(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

def exit():
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)

def litering_by_64(a):
	return '\n'.join([a[i:i + 64] for i in range(0, len(a), 64)])
	
def ec_sign(data, key):
	signature = OpenSSL.crypto.sign(key, data.encode(), "sha256")
	return base58.b58encode(signature)

def check_wallet_build(node):
	build = 4
	try:
		nresponse = requests.get('https://' + str(node) + '/server.php?q=walletbuild')
		data = nresponse.json()
		if int(data['minwalletbuild']) > build:
			return 0
		else:
			return 1
	except Exception as e:
		try:
			nresponse = requests.get('https://' + str(node) + '/server.php?q=walletbuild')
			data = nresponse.json()
			if int(data['minwalletbuild']) > build:
				return 0
			else:
				return 1
		except Exception as e:
			return -1

def check_nodes():
	nodes = ["stlx.online"]
	x = 10000000
	node = "stlx.online"
	print("[INFO] Checking nodes...")
	for n in nodes:
		try:
			nresponse = requests.get('https://' + str(n) + '/server.php?q=getminers')
			data = nresponse.json()
			if int(data['miners']) < x:
				node = n
				x = int(data['miners'])
		except Exception as e:
			print("[ERROR] " + str(n) + " is not responding")
	print("[INFO] " + str(node) + " selected")
	return node

def hash_func(*args) -> bytes:
	"""Concatenate all the arguments and hash the result.
	   Note that the hash function used can be modified
	   in the global parameter HASH_TYPE.
	Args:
		*args: Arguments to concatenate
	Returns:
		str: The hashed string
	"""
	t = b''.join(str(arg).encode('utf-8') for arg in args)
	return hash_functions[HASH_TYPE](t).digest()


def expand(buf, cnt, space_cost) -> int:
	"""First step of the algorithm. Fill up a buffer with
	   pseudorandom bytes derived from the password and salt
	   by computing repeatedly the hash function on a combination
	   of the password and the previous hash.
	Args:
		buf (list str): A list of hashes as bytes.
		cnt (int): Used in a security proof (read the paper)
		space_cost (int): The size of the buffer
	Returns:
		void: Updates the buffer and counter, but does not
		return anything.
	"""
	for s in range(1, space_cost):
		buf.append(hash_func(cnt, buf[s - 1]))
		cnt += 1
	return cnt


def mix(buf, cnt, delta, salt, space_cost, time_cost):
	"""Second step of the algorithm. Mix time_cost number
	   of times the pseudorandom bytes in the buffer. At each
	   step in the for loop, update the nth block to be
	   the hash of the n-1th block, the nth block, and delta
	   other blocks chosen at random from the buffer.
	Args:
		buf (list str): A list of hashes as bytes.
		cnt (int): Used in a security proof (read the paper)
		delta (int): Number of random blocks to mix with.
		salt (str): A user defined random value for security
		space_cost (int): The size of the buffer
		time_cost (int): Number of rounds to mix
	Returns:
		void: Updates the buffer and counter, but does not
		return anything.
	"""
	for t in range(time_cost):
		for s in range(space_cost):
			buf[s] = hash_func(cnt, buf[s - 1], buf[s])
			cnt += 1
			for i in range(delta):
				other = int(hash_func(cnt, salt, t, s, i).hex(), 16) % space_cost
				cnt += 1
				buf[s] = hash_func(cnt, buf[s], buf[other])
				cnt += 1


def extract(buf) -> bytes:
	"""Final step. Return the last value in the buffer.
	Args:
		buf (list str): A list of hashes as bytes.
	Returns:
		str: Last value of the buffer as bytes
	"""
	return buf[-1]


def balloon(password, salt, space_cost, time_cost, delta=3) -> bytes:
	"""Main function that collects all the substeps. As
	   previously mentioned, first expand, then mix, and 
	   finally extract. Note the result is returned as bytes,
	   for a more friendly function with default values
	   and returning a hex string see the function balloon_hash
	Args:
		password (str): The main string to hash
		salt (str): A user defined random value for security
		space_cost (int): The size of the buffer
		time_cost (int): Number of rounds to mix
		delta (int): Number of random blocks to mix with.
	Returns:
		str: A series of bytes, the hash.
	"""
	buf = [hash_func(0, password, salt)]
	cnt = 1

	cnt = expand(buf, cnt, space_cost)
	mix(buf, cnt, delta, salt, space_cost, time_cost)
	return extract(buf)


def balloon_hash(password, salt):
	"""A more friendly client function that just takes
	   a password and a salt and computes outputs the hash in hex.
	Args:
		password (str): The main string to hash
		salt (str): A user defined random value for security
	Returns:
		str: The hash as hex.
	"""
	delta = 6
	time_cost = 12
	space_cost = 24
	return balloon(password, salt, space_cost, time_cost, delta=delta).hex()

def worker(num, address, node, dictmgr, diff, miningid, s):
	dictmgr[1] = 0
	dictmgr[2] = 0
	dictmgr[3] = []
	response = ""
	run = 1
	errors = 0
	
	while(run):
		try:
			nresponse = s.get('https://' + str(node) + '/server.php?q=getminingtemplate&id=' + str(miningid))
			data = nresponse.json()
			dictmgr[1] = data
			nresponse = s.get('https://stlx.online/server.php?q=getpoolbalance&a=' + str(address))
			balance = nresponse.json()
			#print(str(dictmgr[1]))
			if response != dictmgr[1]:
				response = dictmgr[1]
				if num == 0:
					print("[Mining] New block: " + str(dictmgr[1]['result']['height']) + ", Pending balance: " + str(balance['balance']/10000)) + " STLX" # + ", 16block diff: " + str(dictmgr[1]['result']['difficulty']))
			time.sleep(10)
			errors = 0
			try:
				if(len(dictmgr[3]) > 500):
					hashjson = json.dumps(dictmgr[3])
					dictmgr[2] = dictmgr[2] + len(dictmgr[3])
					hashes = []
					dictmgr[3] = hashes
					sresponse = s.post('https://stlx.online/srng.php?wid=' + address, json=hashjson)
			except Exception as e:
				print(e)
		except Exception as e:
			errors = errors + 1
			if errors % 8 == 0:
				print("Connection error. Retrying...")
		except KeyboardInterrupt:
			run = 0
			print('Interrupted')


def mining(num, address, privkey, pubkey, miningid, cores, dictmgr, diff):
	decimal = 10000
	printed = 0
	n = 0
	it = int(time.time())
	response = ""
	run = 1
	errors = 0
	
	while(run):
		try:
			if (int(time.time()) % 30 == num and int(time.time()) != printed):
				printed = int(time.time())
				print("[Mining] " + "Thread " + str(num) + ": " + str(round(n/(int(time.time()+1)-it),2)) + " h/s, Shares: " + str(dictmgr[2]))
			a = randomword(16)
			res = balloon_hash(address + "-" + str(dictmgr[1]['result']['height']) + "-" + str(dictmgr[1]['result']['difficulty']) + "-" + str(dictmgr[1]['result']['prevhash']), a)
			hashes = dictmgr[3]
			hashes.append([a, res])
			dictmgr[3] = hashes
			n = n+1
			errors = 0
		except Exception as e:
			#print(str(e))
			errors = errors + 1
		except KeyboardInterrupt:
			run = 0
			print('Interrupted')

	
def open_wallet(filename, password):
	openfile = filename + '.wallet'
	try:
		f = open(openfile, 'r')
		a = f.read()
		a = litering_by_64(a)
		a = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + a + "\n-----END ENCRYPTED PRIVATE KEY-----\n"
		f.close()
	except Exception as e:
		print("Error opening wallet. File does not exist.")
		print("")
		return 0
	try:
		k = crypto.load_privatekey(crypto.FILETYPE_PEM, a.encode('utf-8'), password.encode('utf-8'))
		a = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8')
	except Exception as e:
		print("Error opening wallet. Invalid password? Please, try again.")
		print("")
		return 0
	rawprivatekey = k
	a = a.replace("-----BEGIN PRIVATE KEY-----", "")
	a = a.replace("-----END PRIVATE KEY-----", "")
	a = a.replace("\n", "")
	ab = base64.b64decode(a)
	ac = base58.b58encode(ab)
	b = crypto.dump_publickey(crypto.FILETYPE_PEM, k).decode('utf-8')
	b = b.replace("-----BEGIN PUBLIC KEY-----", "")
	b = b.replace("-----END PUBLIC KEY-----", "")
	b = b.replace("\n", "")
	publickey = b
	c = base64.b64decode(b)
	d = base58.b58encode(c)
	pubkey = d
	for i in range(0, 9):
		d = hashlib.sha512(d).digest()
	d = hashlib.sha512(d).hexdigest()
	d = base58.b58encode(d)
	address = "STLX" + d.decode('utf-8')
	walletinfo = [address, ac, pubkey, rawprivatekey]
	return walletinfo

def print_help():
	print("")
	print("AVAILABLE COMMANDS:")
	print("");
	print("address: Shows your wallet address.")
	print("balance: Shows your wallet balance.")
	print("exit: Closes the wallet.")
	print("help: Shows this information.")
	print("keys: Shows your private and public keys.")
	print("send: Sends STLX to another address.")
	print("    usage: send destination_address amount")
	print("sendtoken: Sends tokens to another address.")
	print("    usage: send token_symbol destination_address amount")
	print("startmining: Starts the mining process.")
	print("    usage: startmining number_of_threads")
	print("stopmining: Stops the mining process.")
	print("tokens: Shows your tokens balance.")
	print("version: Shows software version.")
	print("")
	return

def suboption(walletinfo):
	suboption = ""
	decimal = 10000
	maxfee = 1000
	minfee = 1
	node = "stlx.online"
	vfee = 0.0001
	server = 1
	ismining = 0
	miningid = randomword(12)
	s = requests.Session()
	if server < 0:
		print("[ERROR!] Unable to connect " + str(node))
		print("")
		exit()
	else:
		print("[INFO] Connected to " + str(node))
		print("")

	if server == 0:
		print("[ERROR] Your wallet application is too old")
		print("[ERROR] Please, update: https://github.com/stlxonline/python-stlx-wallet")
		print("")
		exit()
	print_help()
	while suboption.lower() != "exit":
		suboption = input(walletinfo[0][:8] + "..." + walletinfo[0][-8:] + ": ")
		sys.stdout.write("")
		soption = suboption.lower().split(" ")
		if soption[0] == "address":
			print("")
			print(walletinfo[0])
			print("")
		if soption[0] == "balance":
			print("")
			response = requests.get('https://stlx.online/server.php?q=getbalance&address=' + str(walletinfo[0]))
			bdata = response.json()
			print ("Available: " + str(round(float(bdata['balance'])/decimal, 4)) + " STLX\nLocked: " + str(round(float(bdata['locked'])/decimal, 4)) + " STLX")
			print("")
		if soption[0] == "tokens":
			print("")
			response = requests.get('https://stlx.online/server.php?q=gettokensbalance&address=' + str(walletinfo[0]))
			bdata = response.json()
			for token in bdata['tokensbalance']:
				tresponse = requests.get('https://stlx.online/server.php?q=gettokeninfo&token=' + str(token))
				tdata = tresponse.json()
				print("---- " + str(tdata["token"]["name"]) + " ----")
				print("Available: " + str(round(float(bdata['tokensbalance'][token][1])/100000000, 4)) + " " + str(token) + "\nLocked: " + str(round(float(bdata['tokensbalance'][token][0])/100000000, 4)) + " " + str(token))
				print("")
		if soption[0] == "keys":
			print("")
			print("Private key image: ")
			print(walletinfo[1])
			print("")
			print("Public key image: ")
			print(walletinfo[2])
			print("")
		if soption[0] == "version":
			print("")
			print("v0.0.3, codename: Chur")
			print("")
		if soption[0] == "send":
			print("")
			if len(soption) == 3:
				try:
					amount = float(soption[2])
					amount = amount*decimal
					dest = suboption.split(" ")[1]
					fee = round(amount*vfee, 0)
					if fee > maxfee:
						fee = maxfee
					if fee < minfee:
						fee = minfee
					amount = int(amount)
					fee = int(fee)
					message = ""
					version = "1"
					date = int(time.time())
					txinfo = str(amount) + "-" + str(fee) + "-"  + str(dest) + "-" + str(message) + "-" + str(version) + "-" + str(walletinfo[2]) + "-" + str(date)
					signature = ec_sign(txinfo, walletinfo[3])
					validateinput = ""
					print("Sending " + str(round(float(amount)/decimal, 4)) + " STLX to " + dest + ", with fees: " + str(round(float(fee)/decimal, 4)) + " STLX.")
					print("")
					while validateinput.lower() != "y" and validateinput.lower() != "n":
						validateinput = input("Do it? y/n?")
						if validateinput.lower() == "y":
							print("")
							print("Sending...")
							url = 'https://stlx.online/server.php?q=transfer'
							txvalues = {'amount' : str(amount), 'fee' : str(fee), 'dest' : str(dest), 'pubkey' : str(walletinfo[2]), 'date' : str(date), 'version' : str(version), 'message' : str(message), 'signature' : str(signature) }
							txjson = json.dumps(txvalues)
							txresponse = s.post(url, json=txjson)
							txjsondata = txresponse.json()
							if txjsondata['status'] == 'OK':
								print("[INFO!] Transaction complete! Hash: " + str(txjsondata['response']))
							else:
								print("[ERROR!] Transaction error: " + str(txjsondata['response']))
						elif validateinput.lower() == "n":
							print("[INFO!] Transfer cancelled")
						else:
							print("Invalid option! Please, type y or n")
				except Exception as e:
					print(e)
					print("Invalid arguments!")
					print("[Usage] send destination_address amount")
		if soption[0] == "sendtoken":
			print("")
			if len(soption) == 4:
				try:
					token = str(soption[1])
					tresponse = requests.get('https://stlx.online/server.php?q=gettokeninfo&token=' + str(token))
					tdata = tresponse.json()
					if tdata["status"] == "OK":
						tokendecimal = pow(10, int(tdata["token"]["decimals"]))
						amount = float(soption[3])
						amount = amount*tokendecimal
						dest = suboption.split(" ")[2]
						fee = 100
						amount = int(amount)
						fee = int(fee)
						message = ""
						version = "1"
						date = int(time.time())
						txinfo = str(amount) + "-" + str(fee) + "-"  + str(dest) + "-" + str(message) + "-" + str(version) + "-" + str(walletinfo[2]) + "-" + str(date) + "-" + str(token)
						signature = ec_sign(txinfo, walletinfo[3])
						validateinput = ""
						print("Sending " + str(round(float(amount)/tokendecimal, 4)) + " " + str(token) + " to " + dest + ", with fees: " + str(round(float(fee)/decimal, 4)) + " STLX.")
						print("")
						while validateinput.lower() != "y" and validateinput.lower() != "n":
							validateinput = input("Do it? y/n?")
							if validateinput.lower() == "y":
								print("")
								print("Sending...")
								url = 'https://stlx.online/server.php?q=transfer&symbol=' + str(token)
								txvalues = {'amount' : str(amount), 'fee' : str(fee), 'dest' : str(dest), 'pubkey' : str(walletinfo[2]), 'date' : str(date), 'version' : str(version), 'message' : str(message), 'signature' : str(signature) }
								txjson = json.dumps(txvalues)
								txresponse = s.post(url, json=txjson)
								txjsondata = txresponse.json()
								if txjsondata['status'] == 'OK':
									print("[INFO!] Transaction complete! Hash: " + str(txjsondata['response']))
								else:
									print("[ERROR!] Transaction error: " + str(txjsondata['response']))
							elif validateinput.lower() == "n":
								print("[INFO!] Transfer cancelled")
							else:
								print("Invalid option! Please, type y or n")
					else:
						print("ERROR: " + token + " not exists")
						print("")
				except Exception as e:
					print(e)
					print("Invalid arguments!")
					print("[Usage] send token_symbol destination_address amount")
		if soption[0] == "startmining":
			print("")
			if len(soption) == 2 and ismining == 0:
				try:
					cores = int(soption[1])+1
				except Exception as e:
					#print(e)
					print("Invalid arguments!")
					print("[Usage] startmining number_of_threads")
				else:
					manager = Manager() 
					dictmgr = manager.dict()
					threads = [None] * cores
					for i in range(cores):
						if i == 0:
							params = [i, walletinfo[0], node, dictmgr, 0, miningid, s]
							threads[i] = Process(target=worker, args=(params))
						else:
							params = [i, walletinfo[0], walletinfo[1], walletinfo[2], miningid, cores, dictmgr, 0]
							threads[i] = Process(target=mining, args=(params))
						threads[i].start()
						if i == 0:
							print("[Mining] Started networker thread")
						else:
							print("[Mining] Started thread" + str(i))
						time.sleep(1)
					ismining = 1
			else:
				if ismining == 1:
					print("You are already mining")
				else:
					print("Invalid number of arguments!")
					print("")
					print("[Usage] startmining number_of_threads")
					print("[Example] startmining 4")
					print("[Example] This command starts the mining process with 4 threads")
		if soption[0] == "stopmining":
			print("")
			if ismining == 1:
				for i in range(cores):
					if i == 0:
						print("[Mining] Stopping networker thread")
					else:
						print("[Mining] Stopping thread" + str(i))
					threads[i].terminate()
					threads[i].join()
				threads = []
				ismining = 0
		if soption[0] == "help":
			print_help()
		print("")
	print("")

if __name__ == '__main__':
	multiprocessing.freeze_support()
	try:
		print(" ")
		print("***** STLX TESTNET CLI WALLET *****")
		print(" ")
		print("N: New wallet.")
		print("O: Open wallet.")
		print("X: Close wallet. ")
		print(" ")
		option = ""
		while option.lower() != "n" and option.lower() != "o" and option.lower() != "x":
			option = input("Type an option:  ")
			if option.lower() == "n":
				print(" ")
				print("- Please, provide a name and password for your new wallet.")
				print(" ")
				filename = ""
				while len(filename) < 1:
					filename = input("Filename: ")
					createfile = filename + '.wallet'
					if os.path.isfile(createfile):
						filename = ""
						print("Existing wallet. Please, select another filename")
					else:
						f = open(createfile, 'wb')
					if len(filename) < 1:
						print("Invalid filename!")
						print(" ")
				passwd = ""
				repasswd = " "
				while len(passwd) < 8 or passwd != repasswd:
					print("")
					print("[INFO!] For your security, nothing will be displayed when you type your password. That way, someone who sees your screen can't see the length of your password.")
					passwd = getpass.getpass("Type your password:  ")
					if len(passwd) < 8:
						print("Password must be at least 8 characters.")
						print(" ")
					else:
						repasswd = getpass.getpass("Retype your password:  ")
						if passwd != repasswd:
							print("Passwords doesn't match.")
							print(" ")
				k = crypto.PKey()
				k.generate_key(crypto.TYPE_RSA, 2048)
				a = crypto.dump_privatekey(crypto.FILETYPE_PEM, k, 'aes-256-cbc', passwd.encode('utf-8')).decode('utf-8')
				a = a.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
				a = a.replace("-----END ENCRYPTED PRIVATE KEY-----", "")
				a = a.replace("\n", "")
				f.write(a.encode("utf-8"))
				f.close()
				walletinfo = open_wallet(filename, passwd)
				suboption(walletinfo)
			elif option.lower() == "o":
				print(" ")
				print("- Please, provide the name and password of your wallet.")
				print(" ")
				filename = ""
				while len(filename) < 1:
					filename = input("Filename: ")
					openfile = filename + '.wallet'
					if len(filename) < 1:
						print("Invalid filename!")
						print(" ")
				passwd = ""
				while len(passwd) < 8:
					print("")
					print("[INFO!] For your security, nothing will be displayed when you type your password. That way, someone who sees your screen can't see the length of your password.")
					passwd = getpass.getpass("Type your password:  ")
					if len(passwd) < 8:
						print("Password must be at least 8 characters.")
						print(" ")
				walletinfo = open_wallet(filename, passwd)
				if walletinfo != 0:
					suboption(walletinfo)
				else:
					option = ""
			elif option.lower() == "x":
				exit()
			else:
				print("Invalid option!")
				print(" ")
	except Exception as e:
		print(e)
		print("Interrupted")
	except KeyboardInterrupt:
		print('Interrupted')
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)