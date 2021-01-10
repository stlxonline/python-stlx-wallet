# -*- coding: utf-8 -*-
import OpenSSL
from OpenSSL import crypto, SSL
import multiprocessing
import os.path
import os
import sys
import getpass
import argparse

import balloon
import stlx
import zmqclient

sys.tracebacklimit = 0

def exit():
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument('--disablezmq', type=int, help='0 for enabled. 1 for disabled. Default: 0.')
    args = parser.parse_args()   
    if args.disablezmq == 1:
        print("")
        print("[WARN] ZMQ is disabled via command line.")
        print("")
        zmq = 0
    else:
        zmq = 1
    
    
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
                walletinfo = stlx.open_wallet(filename, passwd)
                stlx.suboption(walletinfo, zmq)
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
                walletinfo = stlx.open_wallet(filename, passwd)
                if walletinfo != 0:
                    stlx.suboption(walletinfo, zmq)
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
