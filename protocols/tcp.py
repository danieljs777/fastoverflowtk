import socket

class Tcp():

    @staticmethod
    def connect(remoteip, port):

        print("\r\n\r\n[!] ##### Connecting to %s" % remoteip)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        try:
            s.connect((remoteip, int(port)))

        except (socket.error, socket.timeout):
            print("[-] Connection error!")
            s = None

        return s

    @staticmethod
    def prepare_command(command):
        return str(command).encode('latin-1')
