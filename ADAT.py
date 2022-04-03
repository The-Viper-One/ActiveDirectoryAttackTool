#!/usr/bin/python3

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'
   




   
   
#Target Information
Username="bob"
Password="pass"
Domain="test.local"
DC="10.10.10.10"
LDAP="DC=Test,DC=local"



# Wordlists
UserList="/usr/share/seclists/Usernames/Names/names.txt"
PassList="/usr/share/wordlists/rockyou.txt"




# DNS
print()
print(color.GREEN + color.BOLD + 'DNS' + color.END)
print("nmap --script dns-brute --script-args dns-brute.threads=12", f'{DC}' ,Domain)
print("dnsenum --dnsserver" ,'{}'.format(DC) + "--enum" ,'{}'.format(Domain))
print()

# Kerberos
print()
print(color.GREEN + color.BOLD + 'Kerberos' + color.END)
print("nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="'{}'.format(Domain),"userdb="'{}'.format(UserList) ,'{}'.format(DC))
print()

# NTP
print()
print(color.GREEN + color.BOLD + 'NTP' + color.END)
print("sudo ntpdate" ,'{}'.format(DC))
print("sudo nmap -sU -p 123 --script ntp-info" ,'{}'.format(DC))
print()

# SMB
print()
print(color.GREEN + color.BOLD + 'SMB' + color.END)
print("enum4linux -u",'{}'.format(Username),"-p", '{}'.format(Password),"-r", '{}'.format(DC),"| grep 'Local User'")
print("smbmap -H", '{}'.format(DC), "-u", '{}'.format(Username), "-p", '{}'.format(Password))
print("smbclient -U", '{}'.format(Username), "-P", '{}'.format(Password), "-L", '\\\\\\\\' + '{}'.format(DC))
print("crackmapexec smb",'{}'.format(DC), "-u", '{}'.format(Username), "-p", '{}'.format(Password))
print("crackmapexec smb",'{}'.format(DC), "-u", '{}'.format(Username), "-p", '{}'.format(Password), "--shares")
print()

# LDAP
print()
print(color.GREEN + color.BOLD + 'LDAP' + color.END)
print("nmap -n -sV --script \"ldap* and not brute\"",'{}'.format(DC))
print("ldapsearch -x -h",'{}'.format(DC), "-D '' -w '' -b", '{}'.format(LDAP), "| grep 'userPrincipalName'")
print("ldapsearch -x -h",'{}'.format(DC), "-D '' -w '' -b", '{}'.format(LDAP), "| grep 'userPrincipalName' | sed 's/userPrincipalName: //'")
print()

# WinRM
print()
print(color.GREEN + color.BOLD + 'WinRM' + color.END)
print("crackmapexec ldap",'{}'.format(DC), "-u", '{}'.format(Username), "-p", '{}'.format(Password))
print("evil-winrm -i",'{}'.format(DC), "-u", '{}'.format(Username), "-p", '{}'.format(Password))
print()


# Arguments

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-n', '--null', action='store_true', 
    help="Displays command for null logins")

args = parser.parse_args()

if args.null:

	print(color.GREEN + color.BOLD + 'LDAP' + color.END)
	print("smbmap -H '10.10.10.10' -u '' -p ''")


