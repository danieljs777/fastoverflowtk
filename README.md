# FastOverflow ToolKit
I started wroting this toolkit whilst studying Buffer Overflow Techniques.

It works through FTP, SMTP, POP, HTTP protocols as well file outputs for playlists exploiting customized variables/commands and supports Vanilla (classic) buffer overflow technique, SEH ByPass and Egghunting. Additionaly, the toolkit makes use of session files and you can restore your walkthrough by default.  

This toolkit is composed by Memory fuzzer, BadChars Testing, Exploitation process automation and soon I will FULLY release the Exploit Generator (right now only Vanilla Exploit Generation). I intend to keep this project very active. Please pull changes before any use.

The toolkit is NOT RECOMMENDED for script kiddies! 


Payloads can be generated through MSFVENOM (shell_reverse_tcp / meterpreter_reverse_tcp) OR you can use your own ASM files.
## Prerequisites

Python 3.8, Metasploit, nasm, nasm_shell

## Usage: 
### Default options :  

```
fast_overflow.py -m [MODE] [-o PLATFORM] [-h HOST] [-p PORT] [-f FIELD] [-U USER] [-P PASS] [-i LOCALIP] [-l LOCALPORT] 

 -m, --mode=MODE           Specify mode for buffer overflow. Accepted : ftp | http | popsmtp | file
 -o, --os=PLATFORM         Target OS Platform for shellcode. Accepted: windows | unix | linux | mac
 -h, --host=HOST           Target to attack. Not used in FILE mode
 -p, --port=PORT           Port to attack. Not used in FILE mode
 -f, --fields=FIELD        Set fields to exploit: user, pass, stor, cookie, user-agent. Separate multiple by commas
 -v, --http-verb=HTTPVERB  Set HTTP method to exploit: GET, HEAD, POST, TRACE, etc. Default: HEAD
 -u, --http-uri=HTTPURI    Set HTTP uri to exploit. Default: /
 -i, --lip=LOCALIP         Local IP for shellcode
 -l, --lport=LOCALPORT     Local Port for shellcode
 -U, --auth-user=USER      User for auth. Default: user
 -P, --auth-pass=PASS      Pass for auth. Default: user
```
## Testing

This tool was tested successfully in Python 3.8 against WarFTPd, Ability FTP Server, SLMail, Konica Minolta, Kolibri and some video players.
NOT FULLY SUPPORTED ON PYTHON 2. Improvements need.

![alt text](https://github.com/danieljs777/fastoverflowtk/blob/master/egghunting.png?raw=true)

## Authors

* **Daniel Jordão** - *Initial work* - [danieljs777](https://github.com/danieljs777)

## License

This project is licensed under the MIT License
