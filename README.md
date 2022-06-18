# ActiveDirectoryAttackTool

ADAT is a small tool used to assist CTF players and Penetration testers with easy commands to run against an Active Directory Domain Controller. This tool is intended to be  utilized using a set of known credentials against the host.

Some of the protocols ADAT prints out commands for:

- DNS
- Kerberos
- LDAP
- MSSQL
- NTP
- RDP
- SMB
- WinRM

Some of the tools ADAT prints out commands for:

- BloodHound
- Crackmapexec (Including modules and PowerShell commands)
- Impacket toolset
- Metasploit
- Nmap
- ldapdomaindump
- ldapsearch
- pywerview
- xfreerdp

ADAT is a work in progress and subject to much change.

ADAT does not execute commands on behalf of the user and is OSCP friendly.

# Usage

Standard usage
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local
```
Usage with LDAP base search
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local -l "DC=Security,DC=Local"
```
Usage with GitHub for script repositories
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local
```
Usage with local system for script repositories (ensure LocalIP and LocalPort variables are set)
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local -L
```



