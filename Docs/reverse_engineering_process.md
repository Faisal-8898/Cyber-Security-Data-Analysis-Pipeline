arning: Permanently added '[167.172.187.18]:2222' (ED25519) to the list of known hosts.
Last login: Thu Apr 23 18:50:22 2026 from 162.243.188.66
root@honeypot-sensors:~# cat ~/.ssh/iot-pipeline-sync.pub 2>/dev/null
root@honeypot-sensors:~# cat ~/.ssh/iot-pipeline-sync.pub 2>/dev/null^C
root@honeypot-sensors:~# nanao
Command 'nanao' not found, did you mean:
  command 'nano' from deb nano (7.2-2ubuntu0.1)
Try: apt install <deb name>
root@honeypot-sensors:~# passwd root
New password:
Retype new password:
passwd: password updated successfully
root@honeypot-sensors:~# grep '^root' /etc/shadow
root:$y$j9T$PZhDCWIz5ofnCsd3F23Vx0$FSEtBCS8evos1wEd5gewasJVCX0jASr3Ln0GQ1hoQj/:20566:0:14600:14:::
root@honeypot-sensors:~#  command 'nano' from deb nano (7.2-2ubuntu0.1)
Try: apt install <deb name>
root@honeypot-sensors:~# passwd root
New password:
Retype new password:
passwd: password updated successfully
root@honeypot-sensors:~# grep '^root' /etc/shadow
root:$y$j9T$PZhDCWIz5ofnCsd3F23Vx0$FSEtBCS8evos1wEd5gewasJVCX0jASr3Ln0GQ1hoQj/:20566:0:14600:14:::
root@honeypot-sensors:~#
-bash: syntax error near unexpected token `('
-bash: syntax error near unexpected token `newline'
root@honeypot-sensors:~#: command not found
Command 'New' not found, did you mean:
  command 'kew' from deb kew (1.11+ds-1)
  command 'new' from deb mmh (0.4-6)
  command 'new' from deb nmh (1.8-1)
Try: apt install <deb name>
Retype: command not found
Command 'passwd:' not found, did you mean:
  command 'passwd' from deb passwd (1:4.13+dfsg1-4ubuntu3.2)
Try: apt install <deb name>
root@honeypot-sensors:~#: command not found
-bash: root:/:20566:0:14600:14:::: No such file or directory
root@honeypot-sensors:~#: command not found
root@honeypot-sensors:~#  command 'nano' from deb nano (7.2-2ubuntu0.1)
Try: apt install <deb name>
root@honeypot-sensors:~# passwd root
New password:
Retype new password:
passwd: password updated successfully
root@honeypot-sensors:~# grep '^root' /etc/shadow
root:$y$j9T$PZhDCWIz5ofnCsd3F23Vx0$FSEtBCS8evos1wEd5gewasJVCX0jASr3Ln0GQ1hoQj/:20566:0:14600:14:::
root@honeypot-sensors:~#^C
root@honeypot-sensors:~# systemctl status serial-getty@ttyS0
● serial-getty@ttyS0.service - Serial Getty on ttyS0
     Loaded: loaded (/usr/lib/systemd/system/serial-getty@.service; enabled-runtime; preset: enabled)
     Active: active (running) since Thu 2026-04-23 18:49:21 UTC; 53min ago
       Docs: man:agetty(8)
             man:systemd-getty-generator(8)
             https://0pointer.de/blog/projects/serial-console.html
   Main PID: 947 (agetty)
      Tasks: 1 (limit: 1110)
     Memory: 240.0K (peak: 1.6M)
        CPU: 12ms
     CGroup: /system.slice/system-serial\x2dgetty.slice/serial-getty@ttyS0.service
             └─947 /sbin/agetty -o "-p -- \\u" --keep-baud 115200,57600,38400,9600 - vt220

Notice: journal has been rotated since unit was started, output may be incomplete.
root@honeypot-sensors:~# faillock --user root
root:
When                Type  Source                                           Valid
root@honeypot-sensors:~# faillock --user root --reset
root@honeypot-sensors:~# systemctl status fail2ban
fail2ban-client status sshd
fail2ban-client status
● fail2ban.service - Fail2Ban Service
     Loaded: loaded (/usr/lib/systemd/system/fail2ban.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-04-23 19:21:34 UTC; 22min ago
       Docs: man:fail2ban(1)
   Main PID: 5579 (fail2ban-server)
      Tasks: 5 (limit: 1110)
     Memory: 22.3M (peak: 24.9M)
        CPU: 1.716s
     CGroup: /system.slice/fail2ban.service
             └─5579 /usr/bin/python3 /usr/bin/fail2ban-server -xf start

Apr 23 19:21:34 honeypot-sensors systemd[1]: Started fail2ban.service - Fail2Ban Service.
Apr 23 19:21:34 honeypot-sensors fail2ban-server[5579]: 2026-04-23 19:21:34,865 fail2ban.configreader   [5579]: WARNING 'allowipv6' not defined in 'Definition'. Using d>
Apr 23 19:21:35 honeypot-sensors fail2ban-server[5579]: Server ready
...skipping...
● fail2ban.service - Fail2Ban Service
     Loaded: loaded (/usr/lib/systemd/system/fail2ban.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-04-23 19:21:34 UTC; 22min ago
       Docs: man:fail2ban(1)
   Main PID: 5579 (fail2ban-server)
      Tasks: 5 (limit: 1110)
     Memory: 22.3M (peak: 24.9M)
        CPU: 1.716s
     CGroup: /system.slice/fail2ban.service
             └─5579 /usr/bin/python3 /usr/bin/fail2ban-server -xf start

Apr 23 19:21:34 honeypot-sensors systemd[1]: Started fail2ban.service - Fail2Ban Service.
Apr 23 19:21:34 honeypot-sensors fail2ban-server[5579]: 2026-04-23 19:21:34,865 fail2ban.configreader   [5579]: WARNING 'allowipv6' not defined in 'Definition'. Using d>
Apr 23 19:21:35 honeypot-sensors fail2ban-server[5579]: Server ready
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~

Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     0
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 0
   |- Total banned:     1
   `- Banned IP list:
Status
|- Number of jail:      1
`- Jail list:   sshd
root@honeypot-sensors:~# systemctl status fail2ban
● fail2ban.service - Fail2Ban Service
     Loaded: loaded (/usr/lib/systemd/system/fail2ban.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-04-23 19:21:34 UTC; 23min ago
       Docs: man:fail2ban(1)
   Main PID: 5579 (fail2ban-server)
      Tasks: 5 (limit: 1110)
     Memory: 22.3M (peak: 24.9M)
        CPU: 1.740s
     CGroup: /system.slice/fail2ban.service
             └─5579 /usr/bin/python3 /usr/bin/fail2ban-server -xf start

Apr 23 19:21:34 honeypot-sensors systemd[1]: Started fail2ban.service - Fail2Ban Service.
Apr 23 19:21:34 honeypot-sensors fail2ban-server[5579]: 2026-04-23 19:21:34,865 fail2ban.configreader   [5579]: WARNING 'allowipv6' not defined in 'Definition'. Using d>
Apr 23 19:21:35 honeypot-sensors fail2ban-server[5579]: Server ready
root@honeypot-sensors:~# fail2ban-client status sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     0
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 0
   |- Total banned:     1
   `- Banned IP list:
root@honeypot-sensors:~# fail2ban-client status
Status
|- Number of jail:      1
`- Jail list:   sshd
root@honeypot-sensors:~# fail2ban-client set sshd unbanip <IP>
-bash: syntax error near unexpected token `newline'
root@honeypot-sensors:~# fail2ban-client set sshd unbanall
2026-04-23 19:45:20,630 fail2ban                [6026]: ERROR   NOK: ("Invalid command 'unbanall' (no set action or not yet implemented)",)
Invalid command 'unbanall' (no set action or not yet implemented)
root@honeypot-sensors:~# ufw status
Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW       Anywhere                   # real SSH
22/tcp                     ALLOW       Anywhere                   # Cowrie SSH
23/tcp                     ALLOW       Anywhere                   # Cowrie Telnet
80/tcp                     ALLOW       Anywhere                   # OpenCanary HTTP
8080/tcp                   ALLOW       Anywhere                   # OpenCanary HTTP-alt / IoT admin panel
21/tcp                     ALLOW       Anywhere                   # OpenCanary FTP
25/tcp                     ALLOW       Anywhere                   # OpenCanary SMTP
7547/tcp                   ALLOW       Anywhere                   # TR-069/CWMP router exploit
5555/tcp                   ALLOW       Anywhere                   # ADB Android/IoT
1883/tcp                   ALLOW       Anywhere                   # MQTT IoT broker
1080/tcp                   ALLOW       Anywhere                   # SOCKS proxy — monetization signal
3128/tcp                   ALLOW       Anywhere                   # HTTP proxy — monetization signal
48101/tcp                  ALLOW       Anywhere                   # Mirai C2 variant port
2222/tcp (v6)              ALLOW       Anywhere (v6)              # real SSH
22/tcp (v6)                ALLOW       Anywhere (v6)              # Cowrie SSH
23/tcp (v6)                ALLOW       Anywhere (v6)              # Cowrie Telnet
80/tcp (v6)                ALLOW       Anywhere (v6)              # OpenCanary HTTP
8080/tcp (v6)              ALLOW       Anywhere (v6)              # OpenCanary HTTP-alt / IoT admin panel
21/tcp (v6)                ALLOW       Anywhere (v6)              # OpenCanary FTP
25/tcp (v6)                ALLOW       Anywhere (v6)              # OpenCanary SMTP
7547/tcp (v6)              ALLOW       Anywhere (v6)              # TR-069/CWMP router exploit
5555/tcp (v6)              ALLOW       Anywhere (v6)              # ADB Android/IoT
1883/tcp (v6)              ALLOW       Anywhere (v6)              # MQTT IoT broker
1080/tcp (v6)              ALLOW       Anywhere (v6)              # SOCKS proxy — monetization signal
3128/tcp (v6)              ALLOW       Anywhere (v6)              # HTTP proxy — monetization signal
48101/tcp (v6)             ALLOW       Anywhere (v6)              # Mirai C2 variant port

root@honeypot-sensors:~# ufw disableufw disable^C
root@honeypot-sensors:~# ufw disable
Firewall stopped and disabled on system startup
root@honeypot-sensors:~# systemctl enable --now serial-getty@ttyS0
Created symlink /etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service → /usr/lib/systemd/system/serial-getty@.service.
root@honeypot-sensors:~# systemctl status serial-getty@ttyS0
● serial-getty@ttyS0.service - Serial Getty on ttyS0
     Loaded: loaded (/usr/lib/systemd/system/serial-getty@.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-04-23 18:49:21 UTC; 57min ago
       Docs: man:agetty(8)
             man:systemd-getty-generator(8)
             https://0pointer.de/blog/projects/serial-console.html
   Main PID: 947 (agetty)
      Tasks: 1 (limit: 1110)
     Memory: 240.0K (peak: 1.6M)
        CPU: 12ms
     CGroup: /system.slice/system-serial\x2dgetty.slice/serial-getty@ttyS0.service
             └─947 /sbin/agetty -o "-p -- \\u" --keep-baud 115200,57600,38400,9600 - vt220

Notice: journal has been rotated since unit was started, output may be incomplete.
root@honeypot-sensors:~# faillock --user root
root:
When                Type  Source                                           Valid
root@honeypot-sensors:~# Connection to 167.172.187.18 closed by remote host.
Connection to 167.172.187.18 closed.
