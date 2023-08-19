import subprocess
import re
import socket   

def identifier():
	
	# Get the IP address of the default network interface
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	local_ip = s.getsockname()[0]
	s.close()

	return local_ip
identifier()
