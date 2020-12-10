# -*- coding: utf-8 -*-
import hashlib
import OpenSSL
from OpenSSL import crypto, SSL
import base64
import base58
import time
import os.path
import os
import requests
import json
import sys
import getpass
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)

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

def exit():
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)

def litering_by_64(a):
	return '\n'.join([a[i:i + 64] for i in range(0, len(a), 64)])

def check_wallet_build(node):
	build = 1
	try:
		nresponse = requests.get('https://' + str(node) + '/server.php?q=walletbuild', timeout=5)
		data = nresponse.json()
		if int(data['minwalletbuild']) > build:
			return 0
		else:
			return 1
	except Exception as e:
		try:
			nresponse = requests.get('https://' + str(node) + '/server.php?q=walletbuild', timeout=5)
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
			nresponse = requests.get('https://' + str(n) + '/server.php?q=getminers', timeout=5)
			data = nresponse.json()
			if int(data['miners']) < x:
				node = n
				x = int(data['miners'])
		except Exception as e:
			print("[ERROR] " + str(n) + " is not responding")
	print("[INFO] " + str(node) + " selected")
	return node

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
	print("version: Shows software version.")
	print("")
	return

def suboption(walletinfo):
	suboption = ""
	decimal = 10000
	node = check_nodes()
	server = check_wallet_build(node)
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
			response = requests.get('https://' + str(node) + '/server.php?q=getbalance&address=' + str(walletinfo[0]), timeout=5)
			bdata = response.json()
			print ("Available: " + str(round(float(bdata['balance'])/decimal, 4)) + " STLX\nLocked: " + str(round(float(bdata['locked'])/decimal, 4)) + " STLX")
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
			print("v0.0.1a, codename: Chur")
			print("")
		if soption[0] == "help":
			print_help()
		print("")
	print("")

if __name__ == '__main__':
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
				a = crypto.dump_privatekey(crypto.FILETYPE_PEM, k, 'aes-256-cfb', passwd.encode('utf-8')).decode('utf-8')
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
