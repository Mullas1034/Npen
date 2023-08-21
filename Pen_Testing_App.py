import nmap_scanner
import os
import re 
import datetime
import threading
import time
import sys
now = datetime.datetime.now()
	
#logo
NMlogo = """
##    ## ######## ######## ##      ##  #######  ########  ##    ##    
###   ## ##          ##    ##  ##  ## ##     ## ##     ## ##   ##     
####  ## ##          ##    ##  ##  ## ##     ## ##     ## ##  ##      
## ## ## ######      ##    ##  ##  ## ##     ## ########  #####       
##  #### ##          ##    ##  ##  ## ##     ## ##   ##   ##  ##      
##   ### ##          ##    ##  ##  ## ##     ## ##    ##  ##   ##     
##    ## ########    ##     ###  ###   #######  ##     ## ##    ##    
##     ##    ###    ########  ########  ######## ########             
###   ###   ## ##   ##     ## ##     ## ##       ##     ##            
#### ####  ##   ##  ##     ## ##     ## ##       ##     ##            
## ### ## ##     ## ########  ########  ######   ########             
##     ## ######### ##        ##        ##       ##   ##              
##     ## ##     ## ##        ##        ##       ##    ##             
##     ## ##     ## ##        ##        ######## ##     ##    

[back] - return to main menu | [refresh] - run network scanner again
[scan] - run a port scan on all IP addresses -if you wish to scan specific IP 
addreses you can by adding their index. [Syntax Example]: 'scan 0 1 3'


 			"""

PSlogo = """
########   #######  ########  ########                           
##     ## ##     ## ##     ##    ##                              
##     ## ##     ## ##     ##    ##                              
########  ##     ## ########     ##                              
##        ##     ## ##   ##      ##                              
##        ##     ## ##    ##     ##                              
##         #######  ##     ##    ##            
 ######   ######     ###    ##    ## ##    ## ######## ########  
##    ## ##    ##   ## ##   ###   ## ###   ## ##       ##     ## 
##       ##        ##   ##  ####  ## ####  ## ##       ##     ## 
 ######  ##       ##     ## ## ## ## ## ## ## ######   ########  
      ## ##       ######### ##  #### ##  #### ##       ##   ##   
##    ## ##    ## ##     ## ##   ### ##   ### ##       ##    ##  
 ######   ######  ##     ## ##    ## ##    ## ######## ##     ##  

[back] - return to main menu

Input Example: 123.456.789.000

	"""
PrvSlogo = """
########  ########  ######## ##     ## ####  #######  ##     ##  ######     
##     ## ##     ## ##       ##     ##  ##  ##     ## ##     ## ##    ##    
##     ## ##     ## ##       ##     ##  ##  ##     ## ##     ## ##          
########  ########  ######   ##     ##  ##  ##     ## ##     ##  ######     
##        ##   ##   ##        ##   ##   ##  ##     ## ##     ##       ##    
##        ##    ##  ##         ## ##    ##  ##     ## ##     ## ##    ##    
##        ##     ## ########    ###    ####  #######   #######   ######     
 ######   ######     ###    ##    ##  ######                                
##    ## ##    ##   ## ##   ###   ## ##    ##                               
##       ##        ##   ##  ####  ## ##                                     
 ######  ##       ##     ## ## ## ##  ######                                
      ## ##       ######### ##  ####       ##                               
##    ## ##    ## ##     ## ##   ### ##    ##                               
 ######   ######  ##     ## ##    ##  ###### 

[back] - return to main menu 

Enter the number that corresponds to the scan you wish to revist. [Syntax Example]: 'Command: 1'
"""
menu = """
	##    ## ########  ######## ##    ## 
	###   ## ##     ## ##       ###   ## 
	####  ## ##     ## ##       ####  ## 
	## ## ## ########  ######   ## ## ## 
	##  #### ##        ##       ##  #### 
	##   ### ##        ##       ##   ### 
	##    ## ##        ######## ##    ##
 
[back] - return to main menu

	[1] Map Network
	[2] Port scan
	[3] Generate Vulnerability scan report 
	[4] Previous Scans
	"""
def clear_console():
	os.system('cls' if os.name == 'nt' else 'clear')

def terminal_reset():
	os.system('stty echo -echoctl')
	
while True:
	#print the menu initially
	clear_console()
	terminal_reset()
	sys.stdin.flush()
	print(menu)
	option = input("Command:")
	option = option.strip()
	
	if option == '1':
		while True:
			clear_console()
			terminal_reset()
			print(NMlogo)
			pattern = r'\bscan\s+\d+(\s+\d+)*\b'
			nmap_scanner.networkMap('')
			sys.stdin.flush()
			option1 = input('Command:')
			option1 = option1.strip()
			
			if option1.lower() == 'refresh':
				print('reloading')
			elif option1.lower() == 'scan':
				nmap_scanner.MassPortScanner()
				print('Scan complete' +' --', now.strftime("%Y-%m-%d %H:%M:%S"))
				nmap_scanner.Report()
				input('Press Enter to exit.')
			elif re.match(pattern, option1):
				scan_parameters = option1.split(' ')
				scan_parameters.pop(0)
				scan_parameters = [int(x) for x in scan_parameters]
				nmap_scanner.SinglePortScan(scan_parameters)
				print('Scan complete'+' --', now.strftime("%Y-%m-%d %H:%M:%S"))
				nmap_scanner.Report()
				option1 = input('Press Enter to exit.')
			elif option1.lower() == 'back':
				break
			else:
				input("\u001b[33mERROR: \u001b[0m Command syntax Error. Press any key for automatic refresh.")
				
			
	elif option == '2':	
		while True:
			clear_console()
			print(PSlogo)
			IP_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
			ip = input('Enter Target IP: ')	
			
			if re.search(IP_pattern, ip):
				nmap_scanner.SinglePortScan(ip.strip())
				print('Scan complete'+' -- ', now.strftime("%Y-%m-%d %H:%M:%S"))
				nmap_scanner.Report()
				option = input('Press Enter to exit.')
			elif ip.lower() == 'back':
				break
			else:
				input("\u001b[33mERROR: \u001b[0m Input not Valid.")

	elif option == '3':
		clear_console()
		#conduct network map
		nmap_scanner.networkMap('')
		#Conduct vulnerability scan
		nmap_scanner.MassPortScanner()
		#generate report file
		nmap_scanner.Report()
		print('Scan complete, Report generated')
		input('Press enter to return to main menu.')

	elif option == '4':
		while True:
			pattern = r'^-?\d+(\.\d+)?$'
			clear_console()
			print(PrvSlogo)
			nmap_scanner.Prev_Scans()	
			file_choice = input('Scan Index:')
			file_choice = file_choice.strip()
			if re.match(pattern, file_choice):
				nmap_scanner.File_Open(int(file_choice))
				option = input('Press any Key to exit.')
			elif file_choice.lower() == 'back':
				break		
			else:
				print("\u001b[33mERROR: \u001b[0m Input not Valid.")
				input("Press Enter to exit.")

	else:
		input("\u001b[33mERROR: \u001b[0m Input not Valid.")

