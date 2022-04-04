#!/bin/bash

set -e
set -u
set -o pipefail


Username="bob";
Password="pass";
Domain="test.local";
DC="10.10.10.10";
LDAP="DC=Test,DC=local";

# Wordlists
UserList="/usr/share/seclists/Usernames/Names/names.txt"


###############################################################################
# Help                                                                         #
################################################################################
Help()
{
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: scriptTemplate [-g|h|v|V]"
   echo "options:"
   echo "g     Print the GPL license notification."
   echo "h     Print this Help."
   echo "v     Verbose mode."
   echo "V     Print software version and exit."
   echo
}

################################################################################
# Options                                                                      #
################################################################################

null() 
{

echo -e '\e[1mSMB\033[0m'
echo -e '\e[1mAnon Mode\033[0m'
echo -e "smbclient -U '' -P '' -L '$DC'"

}

################################################################################
# Options                                                                      #
################################################################################

while getopts "n:" opt; do
  case "$opt" in
    n)	null;;
    h)	Help;;
    ?) echo "Unknown Options";;
    esac
done


red=$'\e[1;31m'
green=$'\e[1;32m'
blue=$'\e[1;34m'
magenta=$'\e[1;35m'
cyan=$'\e[1;36m'
yellow=$'\e[1;93m'
white=$'\e[0m'
bold=$'\e[1m'
norm=$'\e[21m'
reset=$'\e[0m'

echo -e ""
echo -e ""

echo -e "\e[1;31mhttps://github.com/The-Viper-One/ActiveDirectoryAttackTool \e[0m"
echo -e "\e[1;31mhttps://viperone.gitbook.io/pentest-everything/ \e[0m"
echo -e ""

# DNS
echo -e '\e[1mDNS\033[0m'
echo -e ""
echo -e "nmap --script dns-brute --script-args dns-brute.threads=12 '$Domain'"
echo -e "dnsenum --dnsserver '$DC' --enum '$Domain'"
echo -e ""

# Kerberos
echo -e '\e[1mKerberos\033[0m'
echo -e ""
echo -e "nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='$Domain',userdb='$UserList' '$DC'"
echo -e "msfconsole -q -x 'use auxiliary/gather/kerberos_enumusers; set rhost $DC; set lport 4444; set DOMAIN $Domain; set USER_FILE $UserList; exploit'"
echo -e ""

# NTP
echo -e '\e[1mNTP\033[0m'
echo -e ""
echo -e "sudo ntpdate '$DC'"
echo -e "sudo nmap -sU -p 123 --script ntp-info '$DC'"
echo -e ""

# SMB
echo -e '\e[1mSMB\033[0m'
echo -e ""
echo -e "enum4linux -u '$Username' -p '$Password' -r $DC| grep 'Local User'"
echo -e ""
echo -e "smbmap -H '$DC' -u '$Username' -p '$Password'"
echo -e ""
echo -e "smbclient -U '' -P '' -L '$DC'"
echo -e ""
echo -e "crackmapexec smb '$DC' -u '$Username' -p '$Password'"
echo -e "crackmapexec smb '$DC' -u '$Username' -p '$Password' --shares"
echo -e ""

# LDAP
echo -e '\e[1mLDAP\033[0m'
echo -e ""
echo -e "nmap -n -sV --script "ldap* and not brute" '$DC'"
echo -e "ldapsearch -x -h '$DC' -D '' -w '' -b "$LDAP" | grep userPrincipalName"
echo -e "ldapsearch -x -h $DC -D '' -w '' -b "$LDAP" | grep userPrincipalName | sed 's/userPrincipalName: //'"
echo -e ""

#WinRM
echo -e '\e[1mWinRM\033[0m'
echo -e ""
echo -e "crackmapexec winrm '$DC' -u '$Username' -p '$Password'"
echo -e "evil-winrm -i '$DC' -u '$Username' -p '$Password'"
echo -e ""

