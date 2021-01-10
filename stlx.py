# -*- coding: utf-8 -*-
import hashlib
import OpenSSL
from OpenSSL import crypto, SSL
import base64
import base58
import multiprocessing
from multiprocessing import Process, Manager
import time
import requests
import json
import sys

import balloon
import zmqclient

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

def get_data(z, s, uri):
    if s == 0:
        try:
            bdata = json.loads(zmqclient.zmq_request(z, bytes(uri, encoding='utf-8')))
        except:
            print("Getting data error")
    else:
        response = s.get("https://stlx.online/server" + uri)
        bdata = response.json()
    return bdata

def post_data(z, s, uri, data):
    if s == 0:
        try:
            bdata = json.loads(zmqclient.zmq_request(z, bytes(uri + "+" + data, encoding='utf-8')))
        except:
            print("Posting data error")
    else:
        response = s.post("https://stlx.online/server" + uri, json=hashjson)
        try:
            bdata = response.json()
        except:
            bdata = ""
    return bdata

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
            print(f"[ERROR] {n} is not responding")
    print(f"[INFO] {node} selected")
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

def suboption(walletinfo, zmq):
    suboption = ""
    decimal = 10000
    maxfee = 1000
    minfee = 1
    node = "stlx.online"
    vfee = 0.0001
    server = 1
    ismining = 0
    miningid = balloon.randomword(12)
    if zmq:
        z = zmqclient.start_zmq()
        s = 0
    else:
        s = requests.Session()
        z = 0
    if server < 0:
        print(f"[ERROR!] Unable to connect {node}")
        print("")
        exit()
    else:
        print(f"[INFO] Connected to {node}")
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
            print("\n" + walletinfo[0] + "\n")
        if soption[0] == "balance":
            print("")
            bdata = get_data(z, s, "/getbalance/address/" + str(walletinfo[0]))
            av = str(round(float(bdata['balance'])/decimal, 4))
            lk = str(round(float(bdata['locked'])/decimal, 4))
            print (f"Available: {av} STLX\nLocked: {lk} STLX\n")
        if soption[0] == "tokens":
            print("")
            if zmq == 1:
                bdata = get_data(z, s, "/gettokensbalance/address/" + str(walletinfo[0]))
            for token in bdata['tokensbalance']:
                tdata = get_data(z, s, f"/gettokeninfo/token/{token}")
                tokenname = str(tdata["token"]["name"])
                print(f"---- {tokenname} ----")
                av = str(round(float(bdata['tokensbalance'][token][1])/100000000, 4))
                lk = str(round(float(bdata['tokensbalance'][token][0])/100000000, 4))
                print(f"Available: {av} {token}\nLocked: {lk} {token}")
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
                    tdata = get_data(z, s, "/gettokeninfo/token/" + str(token))
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
                            params = [i, walletinfo[0], node, dictmgr, 0, miningid]
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

def worker(num, address, node, dictmgr, diff, miningid):
    dictmgr[1] = 0
    dictmgr[2] = 0
    dictmgr[3] = []
    response = ""
    run = 1
    errors = 0
    
    s = 0
    z = zmqclient.start_zmq()
    
    while(run):
        try:
            data = get_data(z, s, "/getminingtemplate/id/" + str(miningid))
            dictmgr[1] = data
            balance = get_data(z, s, "/getpoolbalance/address/" + str(address))
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
                    sresponse = post_data(z, s, '/submithash/address/' + address, hashjson)
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
            a = balloon.randomword(16)
            res = balloon.balloon_hash(address + "-" + str(dictmgr[1]['result']['height']) + "-" + str(dictmgr[1]['result']['difficulty']) + "-" + str(dictmgr[1]['result']['prevhash']), a)
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