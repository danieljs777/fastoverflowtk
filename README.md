# FastOverflow ToolKit
I made this toolkit whilst studying Buffer Overflow Techniques. This toolkit is composed by Memory fuzzer, BadChars Testing, Exploitation process automation and soon I will release the Exploit Generator. 

It works through FTP, SMTP, POP, HTTP protocols as well generated external files like playlists, exploiting customized variables/commands. 

The toolkit supports Vanilla (classic) buffer overflow technique, SEH ByPass and Egghunting. Additionaly, the toolkit makes use of session files and you can restore your walkthrough by default.

Payloads can be generated through MSFVENOM (shell_reverse_tcp or meterpreter_reverse_tcp) OR you can use your own ASM files.
## Prerequisites

Python 3.8, Metasploit, nasm, nasm_shell

## Usage: 
### Api Controllers :  

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

This tool was tested against WarFTPd, Ability FTP Server, SLMail, Konica Minolta, Kolibri and some video players running in Python 3.8.
NOT FULLY SUPPORTED ON PYTHON 2. Improvements need.


## Authors

* **Daniel Jordão** - *Initial work* - [danieljs777](https://github.com/danieljs777)

## License

This project is licensed under the MIT License
