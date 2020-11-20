import os
import sys
import socket
import time
import getopt
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

            strlen = str(len(buffer))
            print("[!] Injecting %s bytes" % strlen)

            s = Tcp.connect(remoteip, port)

            if (self.config.verbose_lv == 2):
                print(s)

            if (s == None):
                return responses

            print(s.recv(2048))
            print("[.] Trying to overflow %s ..." % field)

            # if (field == "preauth"):
            #     print('[' + strlen + ' bytes]')
            #     s.send(buffer)

            if (field != "user"):
                print(Tcp.prepare_command('USER ' + self.auth_user))
                s.sendall(Tcp.prepare_command("USER " + self.auth_user + "\r\n"))
            else:
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
            print(responses[-1])

            if (field != "pass"):
                print(Tcp.prepare_command('PASS ' + self.auth_pass))
                s.sendall(Tcp.prepare_command('PASS ' + self.auth_pass + '\r\n'))
            else:
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
                print(responses[-1])

            s.close()

        except socket.error as error:
            print(error)
            return []

        return responses

    # FTP FUZZER
    def fuzzer(self, remoteip, port, field, start_size, inc):
        if (inc == None):
            inc = 100

        if (start_size == None):
            size = 100
        else:
            size = start_size

        buffer = "A" * size

        if (field == None):
            field = "user"

        streaming = [True]
        while len(streaming) > 0:

            streaming = (self.inject(remoteip, port, field, buffer, None))

            if (len(streaming) > 0):
                streaming[-1].strip()
                _response = streaming[-1].split(' ')

                # print("[!] ERROR COMMUNICATING TO THE SERVICE " + "|".join(streaming))
                # responsecode = int(_response[0].strip())

                # # 6xx	Protected reply
                # if responsecode > 599:
                # 	print(base64_decode(_response.join(' ')))

                # #5xx	Permanent Negative Completion reply
                # if responsecode > 499:
                # 	return size
                # 	break;

                time.sleep(1)

                size += inc
                buffer = "A" * size

        return size
