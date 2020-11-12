import time


class Raw():

    ############################
    # RAW FUNCTIONS
    ############################
    # RAW FUZZER
    def raw_fuzzer(self, start_size, inc):
        if (inc == None):
            inc = 100

        if (start_size == None):
            size = 100
        else:
            size = start_size

        buffer = "A" * size

        streaming = [True]
        while len(streaming) > 0:

            streaming = (self.raw_inject(buffer, None))

            if (len(streaming) > 0):
                streaming[-1].strip()
                _response = streaming[-1].split(' ')

                time.sleep(1)

                size += inc
                buffer = "A" * size

        return size


    ############################
    ## RAW INJECTION
    def raw_inject(self, buffer, stop_on_field):
        responses = []

        try:

            print("=" * 100)

            strlen = str(len(buffer))

            print("Injecting %s bytes" % strlen)
            s = self.connect(remoteip, port)

            print("Socket")
            print(s)

            if (s == None):
                return responses

            print(s.recv(2048))
            print("Overflowing %s ...")

            print(' [' + strlen + ' bytes]')
            s.send(buffer + '\r\n')

            responses.append(s.recv(2048))
            print(responses[-1])

            s.close()

        except socket.error as error:
            print(error)
            return []

        return responses
