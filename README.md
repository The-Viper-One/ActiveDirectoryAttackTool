# ActiveDirectoryAttackTool


ActiveDirectoryAttackTool (ADAT) tool is used to assist CTF players and Penetration testers with helpful commands to run against an Active Directory Domain Controller. This tool is best utilized using a set of known working credentials against the host.
<br/>

# Usage: General

Standard usage
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local
```
<br/>

Usage with LDAP base search
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local -l "DC=Security,DC=Local"
```
<br/>

Usage with GitHub for script repositories (Target system has internet access)
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local
```
<br/>

# Usage: Systems with no internet access
If the system you are testing has no internet access or is a CTF machine, ADAT will download the required GitHub repositories to your attacking system. Ensure you specify the ```-L``` parameter and set both the LocalIP and LocalPort variables within the script to that of your attacking system.
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d Security.local -L
```
<br/>

# Usage: Standalone Windows Systems

Usage for non domain joined systems, whilst not officially supported by ADAT, many of the commands can be run against a standalone Windows system.
```
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d . -L
bash ADAT.sh -U ViperOne -P Password123 -t 10.10.10.100 -d WORKGROUP -L
```
<br/>

# Supported Protocols
Some of the protocols ADAT prints out commands for:

- DNS
- Kerberos
- LDAP
- MSSQL
- NTP
- RDP
- SMB
- WinRM
<br/>

# Supported Tools
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
<br/>


ADAT produces commands for both external and internal usage.
<br/>


# Examples

![image](https://user-images.githubusercontent.com/68926315/174434219-1a0df5a1-4805-4712-9b3b-8f7bcd9e3996.png)
![image](https://user-images.githubusercontent.com/68926315/174434159-33cd1e39-7ffa-4ca4-821e-3c0b196312aa.png)
<br/>
<br/>
![image](https://user-images.githubusercontent.com/68926315/174434192-43a4cf19-174f-41a8-922e-a84b80fbd4a1.png)
![image](https://user-images.githubusercontent.com/68926315/174434203-25e472d5-39f4-4024-acfc-19d2a83d2ca3.png)

# OSCP

ADAT is OSCP friendly, the commands it prints out might not be. Please be cautious about what commands and scripts invoke before running in an exam environment.

# Disclaimer

The resulting commands printed by ADAT should only be used within an authorized envionment. The author is not responsible for any damages caused.
