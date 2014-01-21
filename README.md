CrunchPwn
=========

---
\#Pwn Linux (pronounced CrunchPwn) is a penetration testing repository/addition for CrunchBang Linux. The packages also work with any Debian Wheezy compliant system. Default themes are built specifically for OpenBox, but feel free to submit themes for various windows managers. Pull requests are gladly accepted, and requests for tools can be made by opening an issue on github.

Setup
=====
Add Key
-------
    curl http://repo.crunchpwn.org/gnupg.key | sudo apt-key add -

/etc/apt/sources.list:
---------------------
    $ echo '## Crunchpwn
    deb http://repo.crunchpwn.org/ purson main' >> /etc/apt/sources.list

Update Sources
--------------
    sudo apt-get update 

Installation
------------
    sudo apt-get install crunchpwn

Screenshots
-----------

![boot splash](http://i.imgur.com/9FhtpWt.png "Boot Menu")

![login screen](http://i.imgur.com/eZKO2G0.png "Login Screen")

![desktop](http://i.imgur.com/jWTjSkG.png "Openbox desktop")
