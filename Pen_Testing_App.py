import nmap_scanner
import os
import re 
import datetime
import threading
import time
import sys
now = datetime.datetime.now()
	
#logos
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

	
def main_menu():
	while True:
		clear_console()
		sys.stdin.flush()
		print(menu)
	#add remote network mapper option
		option = input("")
		option = option.strip()
		if option == '1':
			clear_console()
			print(NMlogo)
			pattern = r'\bscan\s+\d+(\s+\d+)*\b'
			nmap_scanner.networkMap('')

			try:
				sys.stdin.flush()
				option = input('Command:')
				option = option.strip()
				if option.lower() == 'refresh':
					option = '1'
				elif option.lower() == 'scan':
					nmap_scanner.MassPortScanner()
					print('Scan complete' +' --', now.strftime("%Y-%m-%d %H:%M:%S"))
					nmap_scanner.Report()
					option = input('Press Enter to return to main menu.')
				elif re.match(pattern, option):
					scan_parameters = option.split(' ')
					scan_parameters.pop(0)
					scan_parameters = [int(x) for x in scan_parameters]
					nmap_scanner.SinglePortScan(scan_parameters)
					print('Scan complete'+' --', now.strftime("%Y-%m-%d %H:%M:%S"))
					nmap_scanner.Report()
					option = input('Command:')
				elif option.lower() == 'back':
					break
				else:
					input(u"\u001b[33mERROR: \u001b[0m Command syntax Error. Press any key for automatic refresh.")
					option = '1'
			except Exception as e:	
				print(u"\u001b[33mMpS ERROR: \u001b[0m", e)
				option = input("Press any key to return to the main menu.")
				
					
				
		elif option == '2':	
			clear_console()
			print(PSlogo)
			IP_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
			ip = input('Enter Target IP: ')
			if re.search(IP_pattern, ip):
				nmap_scanner.SinglePortScan(ip.strip())
				print('Scan complete'+' -- ', now.strftime("%Y-%m-%d %H:%M:%S"))
				nmap_scanner.Report()
				option = input('Command:')
			elif ip.lower() == 'back':
				main_menu()
			else:
				print(u"\u001b[33mERROR: \u001b[0m Input not Valid.")
				input("")
				option = "2"

#this is for remote network mapping, change to option 3
		elif option == '88':
			clear_console()
			print(NMlogo)
			pattern = r'\bscan\s+\d+(\s+\d+)*\b'
			ip = input("Enter an IP on target network:")
			nmap_scanner.networkMap(ip)
			try:
				option = input('Command:')
				option = option.strip()
				if option.lower() == 'refresh':
					option = '1'
				elif option.lower() == 'scan':
					nmap_scanner.MassPortScanner()
					print('Scan complete' +' --', now.strftime("%Y-%m-%d %H:%M:%S"))
					nmap_scanner.Report()
					option = input('Command:')
				elif re.match(pattern, option):
					scan_parameters = option.split(' ')
					scan_parameters.pop(0)
					scan_parameters = [int(x) for x in scan_parameters]
					nmap_scanner.SinglePortScan(scan_parameters)
					print('Scan complete'+' --', now.strftime("%Y-%m-%d %H:%M:%S"))
					nmap_scanner.Report()
					option = input('Command:')
				elif option.lower() == 'back':
					main_menu()
				else:
					input(u"\u001b[33mERROR: \u001b[0m Command syntax Error. Press any key for automatic refresh.")
					option = '1'
			except Exception as e:	
				print(u"\u001b[33mMpS ERROR: \u001b[0m", e)
				option = input("Press any key for automatic refresh.")

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
			main_menu()

		elif option == '4':
			pattern = r'^-?\d+(\.\d+)?$'
			clear_console()
			print(PrvSlogo)
			nmap_scanner.Prev_Scans()	
			file_choice = input('Scan Index:')
			file_choice = file_choice.strip()
			if re.match(pattern, file_choice):
				nmap_scanner.File_Open(int(file_choice))
				option = input('Press any Key to exit.')
				option = '4'	
			elif file_choice.lower() == 'back':
				option = 'back'
							
			else:
				print(u"\u001b[33mERROR: \u001b[0m Input not Valid.")
				input("")
				option = "4"

		elif option.lower() == "r":
			nmap_scanner.Report()
			option = input('Command:')

		elif option.lower() == 'back':
			main_menu()
		else:
			clear_console()
			print(menu)
			print(u"\u001b[33mERROR: \u001b[0m Input not Valid.")
			option = input("Command:")

main_menu()
