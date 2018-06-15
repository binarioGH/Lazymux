#!/usr/bin/python
## lazymux.py - Lazymux v4.0
# -*- coding: utf-8 -*-
import os
import sys
from time import sleep as timeout
from core.lzmcore import *

def main():
	banner()
	printoptions(("[01] Information Gathering", "[02] Vulnerability Scanner", 
	"[03] Stress Testing", "[04] Password Attacks", "[05] Web Hacking", "06] Exploitation Tools",
	"[07] Sniffing & Spoofing", "[08] Other\n","[10] Exit the Lazymux\n"))
	lazymux = raw_input("lzmx > ")
	
	if lazymux == "1" or lazymux == "01":
		printoptions(("\n[01] Nmap","[02] Red Hawk","[03] D-Tect","[04] sqlmap",
			"[05] Infoga","[06] ReconDog","[07] AndroZenmap","[08] sqlmate", "[09] AstraNmap",
			"[10] WTF","[11] Easymap","[12] BlackBox","[13] XD3v","[14] Crips","[15] SIR",
			"[16] EvilURL","[17] Striker","[18] Xshell","[19] OWScan","[20] OSIF\n",
			"[00] Back to main menu\n"))
		infogathering = raw_input("lzmx > ")
		
		if infogathering == "01" or infogathering == "1":
			download("Nmap", ('apt install nmap'))
		elif infogathering == "02" or infogathering == "2":
			download("RED HAWK", ('apt install git php','git clone https://github.com/Tuhinshubhra/RED_HAWK', 'mv RED_HAWK ~'))
		elif infogathering == "03" or infogathering == "3":
			download("D-Tect",('apt install python2 git','git clone https://github.com/shawarkhanethicalhacker/D-TECT', 'mv D-TECT ~'))
		elif infogathering == "04" or infogathering == "4":
			download("sqlmap",('apt install git python2','git clone https://github.com/sqlmapproject/sqlmap','mv sqlmap ~'))
		elif infogathering == "05" or infogathering == "5":
			download("Infoga",('apt install python2 git','pip2 install requests urllib3 urlparse','git clone https://github.com/m4ll0k/Infoga','mv Infoga ~'))
		elif infogathering == "06" or infogathering == "6":
			download("ReconDog",('apt install python2 git','git clone https://github.com/UltimateHackers/ReconDog','mv ReconDog ~'))
		elif infogathering == "07" or infogathering == "7":
			download("AndroZenmap",('apt install nmap curl','curl -O http://override.waper.co/files/androzenmap.txt','mkdir ~/AndroZenmap','mv androzenmap.txt ~/AndroZenmap/androzenmap.sh'))
		elif infogathering == "08" or infogathering == "8":
		    download("sqlmate",('apt install python2 git','pip2 install mechanize bs4 HTMLparser argparse requests urlparse2','git clone https://github.com/UltimateHackers/sqlmate','mv sqlmate ~'))			
		elif infogathering == "09" or infogathering == "9":
			download("AstraNmap",('apt install git nmap','git clone https://github.com/Gameye98/AstraNmap','mv AstraNmap ~'))
		elif infogathering == "10":
			download("WTF",('apt install git python2','pip2 bs4 requests HTMLParser urlparse mechanize argparse','git clone https://github.com/Xi4u7/wtf','mv wtf ~'))
		elif infogathering == "11":
			download("Easymap",('apt install php git','git clone https://github.com/Cvar1984/Easymap','mv Easymap ~','cd ~/Easymap && sh install.sh'))
		elif infogathering == "12":
			download("BlackBox",('apt install python2 git && pip2 install optparse passlib','git clone https://github.com/jothatron/blackbox','mv blackbox ~'))
		elif infogathering == "13":
			download("XD3v",('apt install curl','curl -k -O https://gist.github.com/Gameye98/92035588bd0228df6fb7fa77a5f26bc2/raw/f8e73cd3d9f2a72bd536087bb6ba7bc8baef7d1d/xd3v.sh','mv xd3v.sh ~/../usr/bin/xd3v && chmod +x ~/../usr/bin/xd3v'))
		elif infogathering == "14":
			download("Crips",("apt install git python2 openssl curl libcurl wget","git clone https://github.com/Manisso/Crips","mv Crips ~"))
		elif infogathering == "15":
			download("SIR",("apt install python2 git","pip2 install bs4 urllib2","git clone https://github.com/AeonDave/sir.git","mv sir ~"))
		elif infogathering == "16":
			download("EvilURL",("apt install git python2 python3","git clone https://github.com/UndeadSec/EvilURL","mv EvilURL ~"))
		elif infogathering == "17":
			download("Striker",('apt install git python2','git clone https://github.com/UltimateHackers/Striker','mv Striker ~','cd ~/Striker && pip2 install -r requirements.txt'))
		elif infogathering == "18":
			download("Xshell",("apt install lynx python2 figlet ruby php nano w3m","git clone https://github.com/Ubaii/Xshell","mv Xshell ~"))
		elif infogathering == "19":
			download("OWScan",('apt install git php','git clone https://github.com/Gameye98/OWScan','mv OWScan ~'))
		elif infogathering == "20":
			download("OSIF",('apt install git python2','pip2 install requests','git clone https://github.com/ciku370/OSIF','mv OSIF ~'))
		elif infogathering == "00" or infogathering == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "2" or lazymux == "02":
		printoptions(("\n[01] Nmap","[02] AndroZenmap","[03] AstraNmap","[04] Easymap","[05] Red Hawk",
			 "[06] D-Tect","[07] Damn Small SQLi Scanner","[08] SQLiv","[09] sqlmap","[10] sqlscan",
			 "[11] Wordpresscan","[12] WPScan","[13] sqlmate","[14] wordpresscan","[15] WTF",
			 "[16] Rang3r","[17] Striker","[18] Routersploit","[19] Xshell","[20] SH33LL",
			 "[21] BlackBox","[22] XAttacker","[23] OWScan\n","[00] Back to main menu\n"))
		vulnscan = raw_input("lzmx > ")
		if vulnscan == "01" or vulnscan == "1":
			download("Nmap", ('apt install nmap'))
		elif vulnscan == "02" or vulnscan == "2":
			download("AndroZenmap",('apt install nmap curl','curl -O http://override.waper.co/files/androzenmap.txt','mkdir ~/AndroZenmap','mv androzenmap.txt ~/AndroZenmap/androzenmap.sh'))		
		elif vulnscan == "03" or vulnscan == "3":
			download("AstraNmap",('apt install git nmap','git clone https://github.com/Gameye98/AstraNmap','mv AstraNmap ~'))
		elif vulnscan == "04" or vulnscan == "4":
			download("Easymap",('apt install php git','git clone https://github.com/Cvar1984/Easymap','mv Easymap ~','cd ~/Easymap && sh install.sh'))			
		elif vulnscan == "05" or vulnscan == "5":
			download("RED HAWK", ('apt install git php','git clone https://github.com/Tuhinshubhra/RED_HAWK', 'mv RED_HAWK ~'))
		elif vulnscan == "06" or vulnscan == "6":
			download("D-Tect",('apt install python2 git','git clone https://github.com/shawarkhanethicalhacker/D-TECT', 'mv D-TECT ~'))
		elif vulnscan == "07" or vulnscan == "7":
			download("DSSS",('apt install python2 git','git clone https://github.com/stamparm/DSSS','mv DSSS ~'))
		elif vulnscan == "08" or vulnscan == "8":
			download('SQLiv',('apt install python2 git','git clone https://github.com/Hadesy2k/sqliv','mv sqliv ~'))
		elif vulnscan == "09" or vulnscan == "9":
			download("sqlmap",('apt install git python2','git clone https://github.com/sqlmapproject/sqlmap','mv sqlmap ~'))
		elif vulnscan == "10":
			download("sqlscan",('apt install git php','git clone http://www.github.com/Cvar1984/sqlscan','mv sqlscan ~'))
		elif vulnscan == "11":
			download("Wordpresscan",('apt install python2 python2-dev clang libxml2-dev libxml2-utils libxslt-dev','git clone https://github.com/swisskyrepo/Wordpresscan','mv Wordpresscan ~','cd ~/Wordpresscan && pip2 install -r requirements.txt'))
		elif vulnscan == "12":
			download("WPScan",('apt install git ruby curl','git clone https://github.com/wpscanteam/wpscan','mv wpscan ~ && cd ~/wpscan','gem install bundle && bundle config build.nokogiri --use-system-libraries && bundle install && ruby wpscan.rb --update'))
		elif vulnscan == "13":
			download("sqlmate",('apt install python2 git','pip2 install mechanize bs4 HTMLparser argparse requests urlparse2','git clone https://github.com/UltimateHackers/sqlmate','mv sqlmate ~'))
		elif vulnscan == "14":
			download("wordpresscan(2)",('apt install nmap figlet git','git clone https://github.com/silverhat007/termux-wordpresscan','cd termux-wordpresscan && chmod +x * && sh install.sh','mv termux-wordpresscan ~'))
		elif vulnscan == "15":
			download("WTF",('apt install git python2','pip2 bs4 requests HTMLParser urlparse mechanize argparse','git clone https://github.com/Xi4u7/wtf','mv wtf ~'))
		elif vulnscan == "16":
			download("Rang3r",("apt install git python2 && pip2 install optparse termcolor","git clone https://github.com/floriankunushevci/rang3r","mv rang3r ~"))
		elif vulnscan == "17":
			download("Striker",('apt install git python2','git clone https://github.com/UltimateHackers/Striker','mv Striker ~','cd ~/Striker && pip2 install -r requirements.txt'))
		elif vulnscan == "18":
			download("Routersploit",('apt install python2 git','pip2 install requests','git clone https://github.com/reverse-shell/routersploit','mv routersploit ~;cd ~/routersploit;pip2 install -r requirements.txt;termux-fix-shebang rsf.py'))
		elif vulnscan == "19":
			download("Xshell",("apt install lynx python2 figlet ruby php nano w3m","git clone https://github.com/Ubaii/Xshell","mv Xshell ~"))
		elif vulnscan == "20":
			download("SH33LL",("apt install git python2","git clone https://github.com/LOoLzeC/SH33LL","mv SH33LL ~"))
		elif vulnscan == "21":
			download("BlackBox",('apt install python2 git && pip2 install optparse passlib','git clone https://github.com/jothatron/blackbox','mv blackbox ~'))
		elif vulnscan == "22":
			download("XAttacker",('apt install git perl','cpnm install HTTP::Request','cpnm install LWP::Useragent','git clone https://github.com/Moham3dRiahi/XAttacker','mv XAttacker ~'))
		elif vulnscan == "23":
			download("OWScan",('apt install git php','git clone https://github.com/Gameye98/OWScan','mv OWScan ~'))
		elif vulnscan == "00" or vulnscan == "0":
			restart_program()
		else:
			wronginput()
	elif lazymux == "3" or lazymux == "03":
		printoptions(("\n[01] Torshammer","[02] Slowloris","[03] Fl00d & Fl00d2","[04] GoldenEye",
			"[05] Xerxes","[06] Planetwork-DDOS","[07] Hydra","[08] Black Hydra","[09] Xshell",
			"[10] santet-online\n","[00] Back to main menu\n"))
		stresstest = raw_input("lzmx > ")
		if stresstest == "01" or stresstest == "1":
			download("Torshammer",('apt install python2 git','git clone https://github.com/dotfighter/torshammer','mv torshammer ~'))
		elif stresstest == "02" or stresstest == "2":
			download("Slowloris",('apt install python2 git','git clone https://github.com/gkbrk/slowloris','mv slowloris ~'))
		elif stresstest == "03" or stresstest == "3":
			download("Fl00d & Fl00d2",('apt install python2 wget','mkdir ~/fl00d','wget http://override.waper.co/files/fl00d.apk','wget http://override.waper.co/files/fl00d2.apk','mv fl00d.apk ~/fl00d/fl00d.py;mv fl00d2.apk ~/fl00d/fl00d2.py'))
		elif stresstest == "04" or stresstest == "4":
			download("GoldenEye",('apt install git python2','git clone https://github.com/jseidl/GoldenEye','mv GoldenEye ~'))
		elif stresstest == "05" or stresstest == "5":
			download("Xerxes",('apt install git','apt install clang','git clone https://github.com/zanyarjamal/xerxes','mv xerxes ~','cd ~/xerxes && clang xerxes.c -o xerxes'))
		elif stresstest == "06" or stresstest == "6":
			planetwork_ddos()
		elif stresstest == "07" or stresstest == "7":
			hydra()
		elif stresstest == "08" or stresstest == "8":
			black_hydra()
		elif stresstest == "09" or stresstest == "9":
			download("Xshell",("apt install lynx python2 figlet ruby php nano w3m","git clone https://github.com/Ubaii/Xshell","mv Xshell ~"))
		elif stresstest == "10":
			download("santet-online",('apt install git python2 && pip2 install requests','git clone https://github.com/Gameye98/santet-online','mv santet-online ~'))
		elif stresstest == "00" or stresstest == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "4" or lazymux == "04":
		printoptions(("\n[01] Hydra","[02] Facebook Brute Force","[03] Facebook Brute Force 2",
			"[04] Facebook Brute Force 3","[05] Black Hydra","[06] Hash Buster","[07] 1337Hash",
			"[08] Cupp","[09] InstaHack","[10] Indonesian Wordlist","[11] Xshell",
			"[12] Social-Engineering","[13] BlackBox","[14] Hashzer","[15] Hasher",
			"[16] Hash-Generator\n","[00] Back to main menu\n"))
		passtak = raw_input("lzmx > ")
		
		if passtak == "01" or passtak == "1":
			download("Hydra",('apt install hydra'))
		elif passtak == "02" or passtak == "2":
			download("Facebook Brute Force",('apt install python2 wget','pip2 install mechanize','mkdir ~/facebook-brute','wget http://override.waper.co/files/facebook.apk','wget http://override.waper.co/files/password.apk','mv facebook.apk ~/facebook-brute/facebook.py;mv password.apk ~/facebook-brute/password.txt'))
		elif passtak == "03" or passtak == "3":
			download("Facebook Brute Force 2",('apt install wget python2','pip2 install mechanize','wget http://override.waper.co/files/facebook2.apk','wget http://override.waper.co/files/password.apk','mkdir ~/facebook-brute-2','mv facebook2.apk ~/facebook-brute-2/facebook2.py && mv password.apk ~/facebook-brute-2/password.txt'))
		elif passtak == "04" or passtak == "4":
			download("Facebook Brute Force 3",('apt install wget python2','pip2 install mechanize','wget http://override.waper.co/files/facebook3.apk','wget http://override.waper.co/files/password.apk','mkdir ~/facebook-brute-3','mv facebook3.apk ~/facebook-brute-3/facebook3.py && mv password.apk ~/facebook-brute-3/password.txt'))
		elif passtak == "05" or passtak == "5":
			download("Black Hydra",('apt install hydra git python2','git clone https://github.com/Gameye98/Black-Hydra','mv Black-Hydra ~'))
		elif passtak == "06" or passtak == "6":
			download("Hash-Buster",('apt install python2 git','git clone https://github.com/UltimateHackers/Hash-Buster','mv Hash-Buster ~'))
		elif passtak == "07" or passtak == "7":
			download("1337Hash",('apt install git python2','git clone https://github.com/Gameye98/1337Hash','mv 1337Hash ~'))
		elif passtak == "08" or passtak == "8":
			download("Cupp",('apt install python2 git','git clone https://github.com/Mebus/cupp','mv cupp ~'))
		elif passtak == "09" or passtak == "9":
			download("InstaHack",('apt install python2 git','pip2 install requests','git clone https://github.com/avramit/instahack','mv instahack ~'))
		elif passtak == "10":
			indonesian_wordlist()
		elif passtak == "11":
			download("Xshell",("apt install lynx python2 figlet ruby php nano w3m","git clone https://github.com/Ubaii/Xshell","mv Xshell ~"))
		elif passtak == "12":
			social()
		elif passtak == "13":
			download("BlackBox",('apt install python2 git && pip2 install optparse passlib','git clone https://github.com/jothatron/blackbox','mv blackbox ~'))
		elif passtak == "14":
			download("Hashzer",('apt install git python2','pip2 install requests','git clone https://github.com/Anb3rSecID/Hashzer','mv Hashzer ~'))
		elif passtak == "15":
			hasher("Hasher",('apt install git python2 && pip2 install passlib binascii progressbar','git clone https://github.com/ciku370/hasher','mv hasher ~'))
		elif passtak == "16":
			download("Hash-Generator",('apt install git python2 && pip2 install passlib progressbar','git clone https://github.com/ciku370/hash-generator','mv hash-generator ~'))
		elif passtak == "00" or passtak == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "5" or lazymux == "05":
		printoptions(("\n[01] sqlmap","[02] Webdav","[03] xGans","[04] Webdav Mass Exploit",
			"[05] WPSploit","[06] sqldump","[07] Websploit","[08] sqlmate","[09] sqlokmed",
			"[10] zones","[11] Xshell","[12] SH33LL","[13] XAttacker","[14] XSStrike",
			"[15] Breacher","[16] OWScan","[17] ko-dork\n","[00] Back to main menu\n"))
		webhack = raw_input("lzmx > ")
		
		if webhack == "01" or webhack == "1":
			download("sqlmap",('apt install git python2','git clone https://github.com/sqlmapproject/sqlmap','mv sqlmap ~'))
		elif webhack == "02" or webhack == "2":
			download("Webdav",('apt install python2 openssl curl libcurl','pip2 install urllib3 chardet certifi idna requests','mkdir ~/webdav','curl -k -O http://override.waper.co/files/webdav.txt;mv webdav.txt ~/webdav/webdav.py'))
		elif webhack == "03" or webhack == "3":
			download("xGans",('apt install python2 curl','mkdir ~/xGans','curl -O http://override.waper.co/files/xgans.txt','mv xgans.txt ~/xGans/xgans.py'))
		elif webhack == "04" or webhack == "4":
			download("Webdav Mass Exploiter",("apt install python2 openssl curl libcurl","pip2 install requests","curl -k -O https://pastebin.com/raw/K1VYVHxX && mv K1VYVHxX webdav.py","mkdir ~/webdav-mass-exploit && mv webdav.py ~/webdav-mass-exploit"))
		elif webhack == "05" or webhack == "5":
			download("WPSploit",('apt update && apt upgrade','apt install python2 git','git clone git clone https://github.com/m4ll0k/wpsploit','mv wpsploit ~'))
		elif webhack == "06" or webhack == "6":
			download("sqldump",('apt install python2 curl','pip2 install google','curl -k -O https://gist.githubusercontent.com/Gameye98/76076c9a282a6f32749894d5368024a6/raw/6f9e754f2f81ab2b8efda30603dc8306c65bd651/sqldump.py','mkdir ~/sqldump && chmod +x sqldump.py && mv sqldump.py ~/sqldump'))
		elif webhack == "07" or webhack == "7":
			download("Websploit",('apt install git python2','pip2 install scapy','git clone https://github.com/The404Hacking/websploit','mv websploit ~'))
		elif webhack == "08" or webhack == "8":
			download("sqlmate",('apt install python2 git','pip2 install mechanize bs4 HTMLparser argparse requests urlparse2','git clone https://github.com/UltimateHackers/sqlmate','mv sqlmate ~'))
		elif webhack == "09" or webhack == "9":
			download("sqlokmed",('apt install python2 git','pip2 install urllib2','git clone https://github.com/Anb3rSecID/sqlokmed','mv sqlokmed ~'))
		elif webhack == "10":
			download("zones",("apt install git php","git clone https://github.com/Cvar1984/zones","mv zones ~"))
		elif webhack == "11":
			download("Xshell",("apt install lynx python2 figlet ruby php nano w3m","git clone https://github.com/Ubaii/Xshell","mv Xshell ~"))
		elif webhack == "12":
			download("SH33LL",("apt install git python2","git clone https://github.com/LOoLzeC/SH33LL","mv SH33LL ~"))
		elif webhack == "13":
			download("XAttacker",('apt install git perl','cpnm install HTTP::Request','cpnm install LWP::Useragent','git clone https://github.com/Moham3dRiahi/XAttacker','mv XAttacker ~'))
		elif webhack == "14":
			download("XSStrike",('apt install git python2','pip2 install fuzzywuzzy prettytable mechanize HTMLParser','git clone https://github.com/UltimateHackers/XSStrike','mv XSStrike ~'))
		elif webhack == "15":
			download("Breacher",('apt install git python2','pip2 install requests argparse','git clone https://github.com/UltimateHackers/Breacher','mv Breacher ~'))
		elif webhack == "16":
			download("OWScan",('apt install git php','git clone https://github.com/Gameye98/OWScan','mv OWScan ~'))
		elif webhack == "17":
			download("ko-dork",('apt install git python2 && pip2 install urllib2','git clone https://github.com/ciku370/ko-dork','mv ko-dork ~'))
		elif webhack == "00" or webhack == "0":
			restart_program()
		else:
			wronginput()
	elif lazymux == "6" or lazymux == "06":
		printoptions(("\n[01] Metasploit","[02] commix","[03] sqlmap","[04] Brutal","[05] A-Rat",
			"[06] WPSploit","[07] Websploit","[08] Routersploit","[09] BlackBox","[10] XAttacker"
			"[11] TXTool\n","[00] Back to main menu\n")) 
		exploitool = raw_input("lzmx > ")
		
		if exploitool == "01" or exploitool == "1":
			download("Metasploit",("apt install git wget curl","wget https://gist.githubusercontent.com/Gameye98/d31055c2d71f2fa5b1fe8c7e691b998c/raw/09e43daceac3027a1458ba43521d9c6c9795d2cb/msfinstall.sh","mv msfinstall.sh ~;cd ~;sh msfinstall.sh"))
		elif exploitool == "02" or exploitool == "2":
			download("Commix",('apt install python2 git','git clone https://github.com/commixproject/commix','mv commix ~'))
		elif exploitool == "03" or exploitool == "3":
			download("sqlmap",('apt install git python2','git clone https://github.com/sqlmapproject/sqlmap','mv sqlmap ~'))
		elif exploitool == "04" or exploitool == "4":
			download("Brutal",())
		elif exploitool == "05" or exploitool == "5":
			a_rat()
		elif exploitool == "06" or exploitool == "6":
			wpsploit()
		elif exploitool == "07" or exploitool == "7":
			websploit()
		elif exploitool == "08" or exploitool == "8":
			download("Routersploit",('apt install python2 git','pip2 install requests','git clone https://github.com/reverse-shell/routersploit','mv routersploit ~;cd ~/routersploit;pip2 install -r requirements.txt;termux-fix-shebang rsf.py'))
		elif exploitool == "09" or exploitool == "9":
			download("BlackBox",('apt install python2 git && pip2 install optparse passlib','git clone https://github.com/jothatron/blackbox','mv blackbox ~'))
		elif exploitool == "10":
			download("XAttacker",('apt install git perl','cpnm install HTTP::Request','cpnm install LWP::Useragent','git clone https://github.com/Moham3dRiahi/XAttacker','mv XAttacker ~'))
		elif exploitool == "11":
			txtool()
		elif exploitool == "00" or exploitool == "0":
			restart_program()
		else:
			wronginput()
	elif lazymux == "7" or lazymux == "07":
		printoptions(("\n[01] KnockMail","[02] Spammer-Grab","[03] Hac","[04] Spammer-Email",
			"[05] SocialFish","[06] santet-online","[07] SpazSMS\n","[00] Back to main menu\n"))
		sspoof = raw_input("lzmx > ")
		
		if sspoof == "01" or sspoof == "1":
			knockmail()
		elif sspoof == "02" or sspoof == "2":
			spammer_grab()
		elif sspoof == "03" or sspoof == "3":
			hac()
		elif sspoof == "04" or sspoof == "4":
			spammer_email()
		elif sspoof == "05" or sspoof == "5":
			socfish()
		elif sspoof == "06" or sspoof == "6":
			sanlen()
		elif sspoof == "07" or sspoof == "7":
			spazsms()
		elif sspoof == "00" or sspoof == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "8" or lazymux == "08":
		printoptions(("\n[01] SpiderBot","[02] ngrokrok","[03] Sudo","[04] Ubuntu","[05] Fedora",
			"[06] Kali Nethunter","[07] VCRT","[08] E-Code","[09] Termux-Styling","[10] PassGen\n",
			"[00] Back to main menu\n"))
		moretool = raw_input("lzmx > ")
		
		if moretool == "01" or moretool == "1":
			spiderbot()
		elif moretool == "02" or moretool == "2":
			ngrok()
		elif moretool == "03" or moretool == "3":
			sudo()
		elif moretool == "04" or moretool == "4":
			ubuntu()
		elif moretool == "05" or moretool == "5":
			fedora()
		elif moretool == "06" or moretool == "6":
			nethunter()
		elif moretool == "07" or moretool == "7":
			vcrt()
		elif moretool == "08" or moretool == "8":
			ecode()
		elif moretool == "09" or moretool == "9":
			stylemux()
		elif moretool == "10":
			passgencvar()
		elif moretool == "00" or moretool == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "10":
		sys.exit()
	
	else:
		wronginput()

if __name__ == "__main__":
	main()