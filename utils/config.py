import os
import sys

class Config:

    localip = "192.168.105.1"
    localport = 7777
    verbose_lv = 2

    remoteip = ""
    remoteport = 0
    mode = ""
    field = ""
    platform = "windows"
    reverse = "windows/shell_reverse_tcp"

    http_method = "HEAD"
    http_uri = ""

    user = "anonymous"
    passwd = "123@test.com"

    fuzzer_type = ""
    fuzzer_buffer = "A"
    offset = 1
    overflow = 0

    session_ignore = False

    badchars = ""
    shellcode = ""

    # jmpesp_add = ""
    # eip = ""
    # esp = ""
    # buffer = ""

    #################################
    # SEHByPass Attributes

    # offset = 1
    nextseh = ""
    seh = ""
    ppr_address = ""
    # payload = "D" * 400
    # nops = 0
    skip_seh = ""  # "\x90\x90\xeb\x06"

    #################################
    # EggHunter Attributes

    #offset = 1
    # eip = "B" * 4
    # esp = "C" * 4
    payload = ""
    nops = 0
    jmpesp_add = ""
    instruction = ""  # "\xeb\xca" #jmp short
    # hunter = ""
    egg = "T00WT00W"
    src_address = ""
    dest_address = ""


