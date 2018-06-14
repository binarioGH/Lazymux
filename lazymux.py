## lazymux.py - Lazymux v3.0
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
	lazymux = input("lzmx > ")
	
	if lazymux == "1" or lazymux == "01":
		printoptions(("\n[01] Nmap","[02] Red Hawk","[03] D-Tect","[04] sqlmap",
			"[05] Infoga","[06] ReconDog","[07] AndroZenmap","[08] sqlmate", "[09] AstraNmap",
			"[10] WTF","[11] Easymap","[12] BlackBox","[13] XD3v","[14] Crips","[15] SIR",
			"[16] EvilURL","[17] Striker","[18] Xshell","[19] OWScan","[20] OSIF\n",
			"[00] Back to main menu\n"))
		infogathering = input("lzmx > ")
		
		if infogathering == "01" or infogathering == "1":
			nmap()
		elif infogathering == "02" or infogathering == "2":
			red_hawk()
		elif infogathering == "03" or infogathering == "3":
			dtect()
		elif infogathering == "04" or infogathering == "4":
			sqlmap()
		elif infogathering == "05" or infogathering == "5":
			infoga()
		elif infogathering == "06" or infogathering == "6":
			reconDog()
		elif infogathering == "07" or infogathering == "7":
			androZenmap()
		elif infogathering == "08" or infogathering == "8":
			sqlmate()
		elif infogathering == "09" or infogathering == "9":
			astraNmap()
		elif infogathering == "10":
			wtf()
		elif infogathering == "11":
			easyMap()
		elif infogathering == "12":
			blackbox()
		elif infogathering == "13":
			xd3v()
		elif infogathering == "14":
			crips()
		elif infogathering == "15":
			sir()
		elif infogathering == "16":
			evilURL()
		elif infogathering == "17":
			striker()
		elif infogathering == "18":
			xshell()
		elif infogathering == "19":
			owscan()
		elif infogathering == "20":
			osif()
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
		vulnscan = input("lzmx > ")
		if vulnscan == "01" or vulnscan == "1":
			nmap()
		elif vulnscan == "02" or vulnscan == "2":
			androZenmap()
		elif vulnscan == "03" or vulnscan == "3":
			astraNmap()
		elif vulnscan == "04" or vulnscan == "4":
			easyMap()
		elif vulnscan == "05" or vulnscan == "5":
			red_hawk()
		elif vulnscan == "06" or vulnscan == "6":
			dtect()
		elif vulnscan == "07" or vulnscan == "7":
			dsss()
		elif vulnscan == "08" or vulnscan == "8":
			sqliv()
		elif vulnscan == "09" or vulnscan == "9":
			sqlmap()
		elif vulnscan == "10":
			sqlscan()
		elif vulnscan == "11":
			wordpreSScan()
		elif vulnscan == "12":
			wpscan()
		elif vulnscan == "13":
			sqlmate()
		elif vulnscan == "14":
			wordpresscan()
		elif vulnscan == "15":
			wtf()
		elif vulnscan == "16":
			rang3r()
		elif vulnscan == "17":
			striker()
		elif vulnscan == "18":
			routersploit()
		elif vulnscan == "19":
			xshell()
		elif vulnscan == "20":
			sh33ll()
		elif vulnscan == "21":
			blackbox()
		elif vulnscan == "22":
			xattacker()
		elif vulnscan == "23":
			owscan()
		elif vulnscan == "00" or vulnscan == "0":
			restart_program()
		else:
			wronginput()
	elif lazymux == "3" or lazymux == "03":
		printoptions(("\n[01] Torshammer","[02] Slowloris","[03] Fl00d & Fl00d2","[04] GoldenEye",
			"[05] Xerxes","[06] Planetwork-DDOS","[07] Hydra","[08] Black Hydra","[09] Xshell",
			"[10] santet-online\n","[00] Back to main menu\n"))
		stresstest = input("lzmx > ")
		if stresstest == "01" or stresstest == "1":
			torshammer()
		elif stresstest == "02" or stresstest == "2":
			slowloris()
		elif stresstest == "03" or stresstest == "3":
			fl00d12()
		elif stresstest == "04" or stresstest == "4":
			goldeneye()
		elif stresstest == "05" or stresstest == "5":
			xerxes()
		elif stresstest == "06" or stresstest == "6":
			planetwork_ddos()
		elif stresstest == "07" or stresstest == "7":
			hydra()
		elif stresstest == "08" or stresstest == "8":
			black_hydra()
		elif stresstest == "09" or stresstest == "9":
			xshell()
		elif stresstest == "10":
			sanlen()
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
		passtak = input("lzmx > ")
		
		if passtak == "01" or passtak == "1":
			hydra()
		elif passtak == "02" or passtak == "2":
			facebook_bruteForce()
		elif passtak == "03" or passtak == "3":
			facebook_BruteForce()
		elif passtak == "04" or passtak == "4":
			fbBrute()
		elif passtak == "05" or passtak == "5":
			black_hydra()
		elif passtak == "06" or passtak == "6":
			hash_buster()
		elif passtak == "07" or passtak == "7":
			leethash()
		elif passtak == "08" or passtak == "8":
			cupp()
		elif passtak == "09" or passtak == "9":
			instaHack()
		elif passtak == "10":
			indonesian_wordlist()
		elif passtak == "11":
			xshell()
		elif passtak == "12":
			social()
		elif passtak == "13":
			blackbox()
		elif passtak == "14":
			hashzer()
		elif passtak == "15":
			hasher()
		elif passtak == "16":
			hashgenerator()
		elif passtak == "00" or passtak == "0":
			restart_program()
		else:
			wronginput()
	
	elif lazymux == "5" or lazymux == "05":
		printoptions(("\n[01] sqlmap","[02] Webdav","[03] xGans","[04] Webdav Mass Exploit",
			"[05] WPSploit","[06] sqldump","[07] Websploit","[08] sqlmate","[09] sqlokmed",
			"[10] zones","[11] Xshell","[12] SH33LL","[13] XAttacker","[14] XSStrike",
			"[15] Breacher","[16] OWScan","[17] ko-dork\n","[00] Back to main menu\n"))
		webhack = input("lzmx > ")
		
		if webhack == "01" or webhack == "1":
			sqlmap()
		elif webhack == "02" or webhack == "2":
			webdav()
		elif webhack == "03" or webhack == "3":
			xGans()
		elif webhack == "04" or webhack == "4":
			webmassploit()
		elif webhack == "05" or webhack == "5":
			wpsploit()
		elif webhack == "06" or webhack == "6":
			sqldump()
		elif webhack == "07" or webhack == "7":
			websploit()
		elif webhack == "08" or webhack == "8":
			sqlmate()
		elif webhack == "09" or webhack == "9":
			sqlokmed()
		elif webhack == "10":
			zones()
		elif webhack == "11":
			xshell()
		elif webhack == "12":
			sh33ll()
		elif webhack == "13":
			xattacker()
		elif webhack == "14":
			xsstrike()
		elif webhack == "15":
			breacher()
		elif webhack == "16":
			owscan()
		elif webhack == "17":
			kodork()
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
			metasploit()
		elif exploitool == "02" or exploitool == "2":
			commix()
		elif exploitool == "03" or exploitool == "3":
			sqlmap()
		elif exploitool == "04" or exploitool == "4":
			brutal()
		elif exploitool == "05" or exploitool == "5":
			a_rat()
		elif exploitool == "06" or exploitool == "6":
			wpsploit()
		elif exploitool == "07" or exploitool == "7":
			websploit()
		elif exploitool == "08" or exploitool == "8":
			routersploit()
		elif exploitool == "09" or exploitool == "9":
			blackbox()
		elif exploitool == "10":
			xattacker()
		elif exploitool == "11":
			txtool()
		elif exploitool == "00" or exploitool == "0":
			restart_program()
		else:
			wronginput()
	elif lazymux == "7" or lazymux == "07":
		print "\n    [01] KnockMail"
		print "    [02] Spammer-Grab"
		print "    [03] Hac"
		print "    [04] Spammer-Email"
		print "    [05] SocialFish"
		print "    [06] santet-online"
		print "    [07] SpazSMS\n"
		print "    [00] Back to main menu\n"
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
		moretool = input("lzmx > ")
		
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