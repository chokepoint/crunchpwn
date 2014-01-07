CrunchPwn
=========

---
\#Pwn Linux (CrunchPwn) is a penetration testing repository/addition for CrunchBang Linux.

Setup
=====
Add Key
-------
    curl http://repo.crunchpwn.org/gnupg.key | sudo apt-key add -

/etc/apt/sources.lst:
---------------------
    $ echo '## Crunchpwn
    deb http://repo.crunchpwn.org/ purson main' >> /etc/apt/sources.lst

Update Sources
--------------
    sudo apt-get update 
    sudo apt-get install <package>
