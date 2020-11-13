import os
import sys

class Config:

    localip = "172.16.18.1"
    localport = 7777
    verbose_lv = 0

    remoteip = ""
    remoteport = 0
    mode = ""
    field = ""
    platform = "windows"
    reverse = "windows/shell_reverse_tcp"

    http_method = "HEAD"
    http_uri = ""

    user = "user"
    passwd = "user"

    badchars = ""
    shellcode = ""

    offset = 1
    overflow = 0
    # jmpesp_add = ""
    # eip = ""
    # esp = ""
    # buffer = ""

    #################################
    # SEHByPass Attributes

    # offset = 1
    nextseh = "B" * 4
    seh = "C" * 4
    ppr_address = ""
    # payload = "D" * 400
    # nops = 0
    skip_seh = ""  # "\x90\x90\xeb\x06"

    #################################
    # EggHunter Attributes

    #offset = 1
    # eip = "B" * 4
    # esp = "C" * 4
    payload = "D" * 400
    nops = 0
    jmpesp_add = ""
    instruction = ""  # "\xeb\xca" #jmp short
    # hunter = ""
    egg = "T00WT00W"
    src_address = ""
    dest_address = ""


