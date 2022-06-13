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
bash ADAT.sh -u ViperOne -p Password123 -i 10.10.10.100 -d Security.local
```
Usage with LDAP base search
```
bash ADAT.sh -u ViperOne -p Password123 -i 10.10.10.100 -d Security.local -l "DC=Security,DC=Local"
```

![image](https://user-images.githubusercontent.com/68926315/168901209-56e8f0af-7fa6-4683-b8c2-f18222c8ad4d.png)
![image](https://user-images.githubusercontent.com/68926315/168901299-0437f26f-d080-4baa-8173-920d34b08f27.png)
![image](https://user-images.githubusercontent.com/68926315/168901342-c8b8029b-f361-41c8-9173-a0e897921fd4.png)
![image](https://user-images.githubusercontent.com/68926315/168901406-7c8bf42d-2821-4696-92d7-9e09c2d28a64.png)

