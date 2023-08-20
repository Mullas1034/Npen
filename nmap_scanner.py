import subprocess
import re
import time
import threading
import sys
import socket
import random
import vulners
from multiprocessing import Process, Manager
import multiprocessing
import os


manager = Manager()
Finished = manager.list()
Data = manager.list()
Scores = manager.list()
Failed = manager.list()
Passed = manager.list()
Vulns = manager.list()
scans = []


	
def Map_loading_animation(stop_event):
	animation = "|/-\\"
	idx = 0
	while not stop_event.is_set():
		print("\r Mapping IP's..." + animation[idx] + '\r', end='')
		idx = (idx + 1) % len(animation)
		time.sleep(0.2)

def loading_animation(stop_event):
	animation = "|/-\\"
	idx = 0
	while not stop_event.is_set():
		print("\r Scanning ..." + animation[idx] + '\r', end='')
		idx = (idx + 1) % len(animation)
		time.sleep(0.2)

def identifier():
	
	# Get the IP address of the default network interface
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	global local_ip
	local_ip = s.getsockname()[0]
	s.close()

	return local_ip

def networkMap(TargetIP):
	Map_animation_stop = threading.Event()
	Map_animation_thread = threading.Thread(target=Map_loading_animation, args=(Map_animation_stop,))
	Map_animation_thread.start()
	IPlist = []
	global IPaddrs
	IPaddrs = []
	if TargetIP == "":
		nmapCommand = 'nmap -sn  '+identifier()+'/24'
	else:
		nmapCommand = 'nmap -sn '+TargetIP+'/24'

	#run the nmap command
	for command in range(3):
		nmapCommandOutput = subprocess.check_output(nmapCommand, shell=True)
		NmapCommandString = nmapCommandOutput.decode('utf8')
		allAddrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", NmapCommandString)
		IPaddrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", NmapCommandString)
		
	for index, i in enumerate(IPaddrs):
		print('[',index,']', i)
	
	print("\nMapping complete  -- ", len(IPaddrs), "IP addresses found")
	Map_animation_stop.set()

def OS_Detection(ip):
	node_OS = ""	
	OS_Command = ['nmap -O '+str(ip)]
	#SubData('Nmap Command used:' + str(OS_Command))
	try:
		output = subprocess.check_output(OS_Command, shell=True, universal_newlines = True)
		OS_output = output.split('\n')
		for line in OS_output:
			if line.find('OS details:') != -1:
				node_OS = line
				#print(line)
				#SubData(line)
				OS_Command.append(line)
				return(OS_Command)
		if node_OS == "":
			#print("--------OS UKNOWN----------")
			
			return("--------OS UKNOWN----------")
			#SubData("--------OS UKNOWN----------")
	except Exception as e:
		#print(u"\u001b[33mOS ERROR: \u001b[0mUnable to reach IP."+str(ip))
		return('ERROR RUNNING OS SCRIPT'+str(e))
		#SubData("OS ERROR:"+str(e))

def CoreInfo():
	return(str(multiprocessing.cpu_count()))

def MassPortScanner():	
	animation_stop = threading.Event()
	animation_thread = threading.Thread(target=loading_animation, args=(animation_stop,))
	sublist = 4
	animation_thread.start()
	proc = []	
	proc_max = 0
	join_max = 0
	run_max = 0
	print('[--------------------------SCAN-----------------------------]')
	processes = [Process(target=MassPortScan, args=(ip_address,)) for ip_address in IPaddrs]
	run_max_range = len(processes)
	last_proc = processes[-1]
	try:	
		for process in processes:
			process.start()
			run_max += 1
			proc.append(process)
			proc_max += 1	
			if proc_max == CoreInfo or process == last_proc:
				for process in proc:
					process.join()
					proc.remove(process)
					join_max += 1
					if join_max == CoreInfo():
						break
				proc_max = 0
				join_max = 0
		while True:
			if run_max == len(Finished):
				break
		
	except Exception as e:
		error = 'SCAN ERROR:'+str(e)
		print(u"\u001b[33m"+error+"\u001b[0m")
		
	print('[--------------------------SCAN-----------------------------]')
	summary()
	animation_stop.set()

def SinglePortScan(IPs):
	animation_stop = threading.Event()
	animation_thread = threading.Thread(target=loading_animation, args=(animation_stop,))
	animation_thread.start()
	pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
	proc = []
	sublist = 4
	proc_max = 0
	join_max = 0
	run_max = 0
	try:
		print('[--------------------------SCAN-----------------------------]')
		if type(IPs) == list:
			
			processes = [Process(target=portscan, args=(IPaddrs[i],))for i in IPs]
			last_proc = processes[-1]
			for process in processes:		
				process.start()
				proc.append(process)
				run_max += 1
				proc_max += 1
				if proc_max == CoreInfo() or process == last_proc:
					for process in proc:
						process.join()
						proc.remove(process)
						join_max += 1
						if join_max == CoreInfo():
							break
					proc_max = 0
					join_max = 0
				while True:	
					if run_max == len(Finished):
						break
		else:
			process = [Process(target=MassPortScan, args=(IPs,))]
			for i in process:
				i.start()
				i.join()
		
	except Exception as e:
		print(e)

	print('[--------------------------SCAN-----------------------------]')
	summary()
	animation_stop.set()
	

def Vuln_Scan(IP, ports):
	results = []
	score_pattern = r"\d+\.\d+"	
	CVE_pattern = r"CVE-\d{4}-\d{4,7}"
	url_pattern = r'https?://\S+'
	#print('\n[-------------VULNERABILITY SCAN-------------]')
	banner = '[-------------VULNERABILITY SCAN-------------]'
	try:

		for port in ports:
			nmapCommand = 'sudo nmap --script nmap-vulners/ -sV '+IP+" -p "+re.sub(r'\D', '',port)
			nmapCommandOutput = subprocess.check_output(nmapCommand, stderr=subprocess.DEVNULL, shell=True)
			NmapCommandString = nmapCommandOutput.decode('utf8')
			for i in NmapCommandString.split('\n'):
				if i.find('cve') != -1:
					results.append(i)
				CVE = re.findall(CVE_pattern, i)
				score = re.findall(score_pattern, i)
				URL = re.findall(url_pattern, i)
				if CVE and score and URL:
					score = float(score[0])
					Red_intensity = int(score * 25.5)				
					Green_intensity = int(255 - score * 25.5)
					colour_code = f"\033[38;2;{Red_intensity};{Green_intensity};0m"
					reset_code = "\033[0m"
					coloured_text = f"{colour_code}{score:.2f}{reset_code}"
			
					Failed.append('FAILED')					
					#SubData(port+':')
					#print('Vulnerability ID:\033[31m'+CVE[0]+'\033[0m')
					#Data.append('Vulnerability ID:'+CVE[0])
					Vulns.append(CVE[0])
					#print('Severity Score:'+coloured_text)	
					#Data.append('Severity Score:'+score)
					Scores.append(score)
					#print('More Info:', URL[0])
					#Data.append('More Info:'+URL[0])
					data = "ID:"+str(CVE[0])+"|"+"Score:"+str(score)+"|"+"URL:"+str(URL[0])					
					#SubData(data)

					print(str(IP)+'--'+"\033[31mFAILED \033[0m")
					return(banner+'\n'+port+':'+'\n'+data+'\n'+banner+'\n'+'FAILED'+'\n')
		if len(results) == 0:
			Passed.append('PASSED')
			Scores.append(0.0)			
			#SubData('PASSED\n')
			print(str(IP)+'--'+"\033[32mPASSED\033[0m            ")	
			return('PASSED')
	except Exception as e:
		#SubData('ERROR'+str(e) )
		return('VS ERROR'+str(e))
					
def summary():
	try:
		joined_list = []
		for i in Passed:
			joined_list.append(i)
		for x in Failed:
			joined_list.append(x)
		Passed_per = (len([ele for ele in joined_list if ele == 'PASSED']) / len(joined_list)) * 100
		Failed_per = (len([ele for ele in joined_list if ele == 'FAILED']) / len(joined_list)) * 100
		print('FAILED:', str(round(Failed_per,2))+'%')
		print('PASSED:', str(round(Passed_per,2))+'%')
		print('Number of Vulnerabilities:', len(Vulns))
		print('Average Severity of Vulnerabilities:', str(sum(Scores)/len(Scores)))
	except Exception as e:
		print(u"\u001b[33mSUMMARY ERROR: \u001b[0m ", e)

		

def Report():
	try:
		file_name = "NPEN_REPORT#"+str(random.randint(0,999))+'.txt'
		with open(file_name, 'w') as file:
			#machines found

			file.write('During the scan '+ str(len(IPaddrs))+ ' were found:')

			for i in IPaddrs:
				file.write('\n')
				file.write(i)
			#the open ports to all the machines
			file.write('\n')
			file.write('The following machines have their open ports listed:\n')
			for x in Data:
				for i in x:
					try:
						file.write(i)
						file.write('\n')
					except:
						for y in i:
							file.write(y)
							file.write('\n')
			file.write('\n')
			file.write('Overall score:'+str(round(sum(Scores)/len(Scores),2)))
			file.close()
			print(os.path.abspath(file_name), " Has been generated.")
			List_Cache_reset()
			

	except Exception as e:
		file_name = "NPEN_REPORT#"+str(random.randint(0,999))+'.txt'
		with open(file_name, 'w') as file:
			#machines found
			file.write('Single Machine Scan')
			file.write('\n')
			#the open ports to all the machines
			file.write('\n')
			file.write('The following machines have their open ports listed:\n')
			for x in Data:
				for i in x:
					try:
						file.write(i)
						file.write('\n')
					except:
						for y in i:
							file.write(y)
							file.write('\n')
			file.write('\n')
			file.write('Overall score:'+str(round(sum(Scores)/len(Scores),2)))
			file.close()
			print(file_name, " Has been generated.")

def List_Cache_reset():	
	del Failed[:]
	del Passed[:]
	del Finished[:]
	del Vulns[:]
	del Data[:]
	del Scores [:]
	
def Prev_Scans():
	
	pattern = r"^\./NPEN_REPORT#\d{3}\.txt$"
	Prev_Scans = []
	Files = []
	try:
		for root, dirs, files in os.walk('/'):
			for file_name in files:
				file_path = os.path.join(root,file_name)
				if re.match('NPEN_REPORT', file_name) and re.search('trash', file_path.lower()) == None:
					Files.append(file_name)
					Prev_Scans.append(os.path.join(file_path))	
					scans.append(os.path.join(file_path))	
					
		for i in Files:
			print('['+str(Files.index(i))+'] -- '+i)
		
		if len(Files) == 0:
			print('NO PREVIOUS SCANS')
		print('\n')

		
	except Exception as e:
		error = 'ERROR: Unable to reach:'+str(e)
		print(u"\u001b[33m"+error+"\u001b[0m")
		print(e)

def File_Open(index):
	try:
		file_name = scans[index]
		print(file_name)
		with open(file_name, "r") as file:
			for i in file:
				print(i)
	except Exception as e:
		return('FO ERROR:'+str(e))
	


def portscan(ip):
	test2 = []
	ports = []
	port_data = []
	nmap_command = ["nmap", "-sV", ip]
	OS_Detection(ip)
	output = subprocess.check_output(nmap_command, shell=False, stderr=subprocess.DEVNULL,universal_newlines=True)
	for i in output.split('\n'):
		if i.find('(1 host up)') != -1:
			Con = True
			break
		else:
			Con = False
	if Con == True:
		try:
			test2.append("Nmap command used:"+str(nmap_command))
			pattern = r"\d+\/[a-zA-Z]+"
			score = r"\d+\.\d+"
			#print('[--------OPEN PORTS-------]')
			test2.append('[--------OPEN PORTS-------]')
			for line in output.split('\n'):
				if line.find('open') != -1:
					line_data = line.split(" ")
					tail = ["".join(line_data[3:])]
					port_data = [line_data[:3] + [tail]]
					#print(line)
					test2.append(line)
					for x in port_data:
						ports.append(x[0])
						
						#print(ports(x[0]))
			if len(ports) == 0:
				test2.append('NO OPEN PORTS')
				#SubData.append('NO OPEN PORTS')

			test2.append(Vuln_Scan(ip, ports))
		except subprocess.CalledProcessError as e:
			error = "PS ERROR:"+str(e)
			print(u"\u001b[33m"+error+str(ip_address)+"\u001b[0m")
			test2.append(error)			
			#SubData(error)

	else:
		error = 'ERROR: Unable to reach:'+str(ip_address)
		print(u"\u001b[33m"+error+"\u001b[0m")
		test2.append(error)
	Finished.append(ip)
	Data.append(test2)
	
	
def MassPortScan(ip_address):
	test = []
	#SubData(ip_address)
	ports = []
	port_data = []
	nmap_command = ["nmap", "-sV", ip_address]
	output = '\r' + subprocess.check_output(nmap_command, shell=False, 
			stderr=subprocess.DEVNULL,universal_newlines=True)
	
	for i in output.split('\n'):
		if i.find('(1 host up)') != -1:
			Con = True
			break
		else:
			Con = False
		
	if Con == True:
		try:
			test.append(ip_address)
			test.append('Commands used:\n'+str(nmap_command))
			test.append(OS_Detection(ip_address))
			#print('[--------OPEN PORTS-------]')
			test.append('[--------OPEN PORTS-------]')
			#SubData('[--------OPEN PORTS-------]')
			for line in output.split('\n'):
				if line.find('open') != -1:
					line_data = line.split(" ")
					tail = ["".join(line_data[3:])]
					port_data = [line_data[:3] + [tail]]
					#print(line)
					test.append(line)
					#SubData(line)
					for x in port_data:
						ports.append(x[0])
						#print(str(ports(x[0])))
			if len(ports) == 0:
				#print("NO OPEN PORTS         ")
				test.append('NO OPEN PORTS')				
				#SubData('NO OPEN PORTS')
			#result = ip_address+'--'+Vuln_Scan(ip_address, ports)
			test.append(Vuln_Scan(ip_address, ports))
			#print(result)
			#SubData(result)
		except Exception as e:
			error = "MS1 ERROR:"+str(e)
			print(u"\u001b[33m"+error+str(ip_address)+"\u001b[0m")
			test.append(error)			
			#SubData(error)
	else: 
		error = 'ERROR: Unable to reach:'+str(ip_address)
		print(u"\u001b[33m"+error+"\u001b[0m")
		test.append(error)
		#SubData(error)
	Finished.append(ip_address)
	Data.append(test)



