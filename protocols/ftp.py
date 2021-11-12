import os
import string
import sys
import socket
import time
import getopt
import random
from struct import *
import subprocess
import re
import binascii
from past.builtins import execfile
from protocols import *
from buffers import *
from protocols.tcp import Tcp

class Ftp:

    auth_user = "anonymous"
    auth_pass = "123@test.com"

    def __init__(self, config):
        self.config = config
        if(config.user != ""):
            self.auth_user = config.user

        if (config.passwd != ""):
            self.auth_pass = config.passwd

        return None


    ############################
    # FTP FUNCTIONS

    ############################
    ## FTP INJECTION

    def inject(self, remoteip, port, field, buffer, stop_on_field):
        responses = []

        field = field.lower()

        try:

            if (stop_on_field == None):
                stop_on_field = False

            if (self.config.verbose_lv == 2):
                print("BUFFER BEGIN" + ("=" * 100))
                print(buffer)
                print(("=" * 100) + " BUFFER END")

            if not isinstance(buffer, str):
                strlen = str(len(buffer.decode('latin-1').strip()))
            else:
                strlen = str(len(buffer.strip()))

            print("[!] Injecting %s bytes on %s" % (strlen, field.upper()))

            s = Tcp.connect(remoteip, port)

            if (self.config.verbose_lv == 2):
                print(s)

            if (s == None):
                return responses

            if (self.config.verbose_lv < 0):
                print(s.recv(2048))

            # if (field == "preauth"):
            #     print('[' + strlen + ' bytes]')
            #     s.send(buffer)

            if (field != "user"):
                if (self.config.verbose_lv > 0):
                    print(Tcp.prepare_command('USER ' + self.auth_user))

                s.sendall(Tcp.prepare_command("USER " + self.auth_user + "\r\n"))
            else:
                if (self.config.verbose_lv > 0):
                    print(Tcp.prepare_command('USER [' + strlen + ' bytes]'))

                if not isinstance(buffer, str):
                    s.sendall(Tcp.prepare_command('USER ' + buffer.decode('latin-1') + '\r\n'))
                else:
                    s.sendall(Tcp.prepare_command('USER ' + buffer + '\r\n'))

            # if(stop_on_field):
            # response = s.recv(2048)
            # print(response)
            # 	s.close()
            # 	return response

            responses.append(s.recv(2048))
            if (self.config.verbose_lv > 0):
                print(responses[-1])

            if (field != "pass"):
                if (self.config.verbose_lv > 0):
                    print(Tcp.prepare_command('PASS ' + self.auth_pass))

                s.sendall(Tcp.prepare_command('PASS ' + self.auth_pass + '\r\n'))
            else:
                if (self.config.verbose_lv > 0):
                    print(Tcp.prepare_command('PASS [' + strlen + ' bytes]'))

                if not isinstance(buffer, str):
                    s.sendall(Tcp.prepare_command('PASS ' + buffer.decode('latin-1') + '\r\n'))
                else:
                    s.sendall(Tcp.prepare_command('PASS ' + buffer + '\r\n'))

            # if(stop_on_field):
            # response = s.recv(2048)
            # print(response)
            # 	s.close()
            # 	return response

            responses.append(s.recv(2048))
            if (self.config.verbose_lv == 2):
                print(responses[-1])

            if (field != "user" and field != "pass"):
                print(field + ' [ ' + strlen + ' bytes ] ')

#                print buffer.encode('latin-1')  # + ' bytes]')

                # _buf = (field + ' ' + buffer + '\r\n').encode()
                #
                # s.sendall(_buf)
                # if (sys.version_info >= (3, 0)):
                #     print(type(field))
                #     print(type(buffer))
                #     #cmd = bytes(field + ' ' + buffer.decode('latin-1') + '\r\n', 'latin-1')
                #     cmd = (field + ' ' + buffer.decode('latin-1') + '\r\n').encode('latin-1')
                #
                #     cmd = self.prepare_command((field + ' ' + buffer.decode('latin-1') + '\r\n'))
                #
                #     print(cmd)
                # else:
                # print(type(field))
                # print(type(buffer))

                if not isinstance(buffer, str):
                    cmd = Tcp.prepare_command(field + ' ' + buffer.decode('latin-1') + '\r\n')
                else:
                    cmd = Tcp.prepare_command(field + ' ' + buffer + '\r\n')

                s.sendall(cmd)

                # if(stop_on_field):
                # response = s.recv(2048)
                # print(response)
                # 	s.close()
                # 	return response
                responses.append(s.recv(2048))
                print(responses)

            s.close()

        except socket.error as error:
            print(error)
            return []

        return responses

    # FTP FUZZER
    def fuzzer(self, remoteip, port, field, start, stop, step):

        if (field == None):
            field = "user"

        size = 0

        for size in range(int(start), int(stop) + int(step), int(step)):

            if (self.config.fuzzer_type.lower() == "printables"):
                fuzzer_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))
            else:
                fuzzer_buffer = "A" * size

            streaming = (self.inject(remoteip, port, field, fuzzer_buffer, None))

            print(streaming)

            if (len(streaming) > 0):
                _stream = streaming[-1].decode('latin-1').strip()
                _response = _stream.split(' ')
                time.sleep(1)

            else:
                break

                # print("[!] ERROR COMMUNICATING TO THE SERVICE " + "|".join(streaming))
                # responsecode = int(_response[0].strip())

                # # 6xx	Protected reply
                # if responsecode > 599:
                # 	print(base64_decode(_response.join(' ')))

                # #5xx	Permanent Negative Completion reply
                # if responsecode > 499:
                # 	return size
                # 	break;

                #size += step
                # self.config.fuzzer_buffer = "A" * size

        return size

    def output_stream(self, field):

        stream = ""

        if (field != "user"):
            stream += (" " * 4) + 's.sendall(("USER "' + self.auth_user + '"\\r\\n" + ").encode("latin-1"))\r\n'
            stream += (" " * 4) + "print(s.recv(2048))\r\n"
        else:
            stream += (" " * 4) + 's.sendall(("USER ").encode("latin1") + buffer + ("\\r\\n").encode("latin-1"))\r\n'
            stream += (" " * 4) + "print(s.recv(2048))\r\n"

        if (field != "pass"):
            stream += (" " * 4) + 's.sendall(("PASS ' + self.auth_pass + '\\r\\n").encode("latin-1"))\r\n'
            stream += (" " * 4) + "print(s.recv(2048))\r\n"
        else:
            stream += (" " * 4) + 's.sendall(("PASS ").encode("latin1") + buffer + ("\\r\\n").encode("latin-1"))\r\n'
            stream += (" " * 4) + "print(s.recv(2048))\r\n"

        if (field != "user" and field != "pass"):
            stream += (" " * 4) + 's.sendall(("' + field + ' ").encode("latin1") + buffer + ("\\r\\n").encode("latin-1"))\r\n'
            stream += (" " * 4) + "print(s.recv(2048))\r\n"

        return stream
