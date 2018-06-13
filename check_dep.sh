#!/bin/sh


sudo apt-get install python python-pip
if [ ! -f "/usr/lib/libcapstone.a" ]; then
	echo "[+] installing libcapstone-dev..."
	sudo apt-get install libcapstone-dev
fi

if [ ! -d "/usr/local/lib/python2.7/dist-packages/cle/" ]; then
	echo "[+] installing cle..."
	sudo pip install cle
fi

sudo apt-get install msr-tools

echo "[+] All conditions have been satisfied."
