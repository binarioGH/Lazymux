#!/usre/bin/python
## lzmcore.py - useful module of Lazymux
# -*- coding: utf-8 -*-
import os
import sys
import time



def download(name, commands):
	print('\n###### Installing {}'.format(name))
	os.system('apt update && apt upgrade')
	for command in commands:
		os.system(command)
	print('###### Done')
	backtomenu_option()

def printoptions(options):
	for option in options:
		print(option)

lazymux_banner = """
.-.                                           
: :                                           
: :    .--.  .---. .-..-.,-.,-.,-..-..-..-.,-.
: :__ ' .; ; `-'_.': :; :: ,. ,. :: :; :`.  .'
:___.'`.__,_;`.___;`._. ;:_;:_;:_;`.__.':_,._;
                    .-. :                     
                    `._.'                     
"""
backtomenu_banner = """
  [99] Back to main menu
  [00] Exit the Lazymux
"""

def restart_program():
	python = sys.executable
	os.execl(python, python, * sys.argv)
	curdir = os.getcwd()

def wronginput():
	print("\nERROR: Wrong Input")
	time.sleep(2)
	restart_program()



def backtomenu_option():
	print (backtomenu_banner)
	backtomenu = input("lzmx > ")
	
	if backtomenu == "99":
		restart_program()
	elif backtomenu == "00":
		sys.exit()
	else:
		wronginput()

def banner():
	print (lazymux_banner)