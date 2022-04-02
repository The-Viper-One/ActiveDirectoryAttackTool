#!/bin/bash

Username="bob"
Password="pass"
Domain="test.domain"
DC="10.10.10.10"
b = ""\\\\""


echo -e '\e[1mDNS\033[0m'
echo -e ""
echo -e "nmap --script dns-brute --script-args dns-brute.threads=12 '$Domain'"
echo -e "dnsenum --dnsserver '$DC' --enum '$Domain"
echo -e ""

echo -e '\e[1mKerberos\033[0m'
echo -e ""
echo -e ""

echo -e '\e[1mNTP\033[0m'
echo -e ""
echo -e "sudo ntpdate '$DC'"
echo -e "sudo nmap -sU -p 123 --script ntp-info '$DC'"
echo -e ""

echo -e '\e[1mSMB\033[0m'
echo -e ""
echo -e "smbmap -H '$DC' -u '$Username' -p '$Password'"
echo -e ""
echo -e "smbclient -U '' -P '' -L $b'$DC'"
echo -e ""
echo -e "crackmapexec smb '$DC' -u '$Username' -p '$Password'"
echo -e "crackmapexec smb '$DC' -u '$Username' -p '$Password' --shares"
echo -e ""

echo -e '\e[1mLDAP\033[0m'
echo -e ""
echo -e ""

echo -e '\e[1mWinRM\033[0m'
echo -e ""
echo -e "crackmapexec winrm '$DC' -u '$Username' -p '$Password'"
echo -e "evil-winrm -i '$DC' -u '$Username' -p '$Passowrd'"
echo -e ""
