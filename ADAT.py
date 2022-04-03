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


Username="bob"
Password="pass"
Domain="test.local"
DC="10.10.10.10"
LDAP="DC=Test,DC=local"



# Wordlists
UserList="/usr/share/seclists/Usernames/Names/names.txt"

print('{}'.format(DC))
print(color.GREEN + color.BOLD + 'DNS' + color.END)
print("nmap --script dns-brute --script-args dns-brute.threads=12", DC ,Domain)
print("dnsenum --dnsserver" ,'{}'.format(DC) + "--enum" ,'{}'.format(Domain))

