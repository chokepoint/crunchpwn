CrunchPwn
=========

---
\#Pwn Linux (pronounced CrunchPwn) is a penetration testing repository/addition for CrunchBang Linux. The packages also work with any Debian Wheezy compliant system. Default themes are built specifically for OpenBox, but feel free to submit themes for various windows managers. Pull requests are gladly accepted, and requests for tools can be made by opening an issue on github.

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

Installation
------------
    sudo apt-get install crunchpwn
