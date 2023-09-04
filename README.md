# Npen
Npen is an application that aims to make cyber security operations simple. 

Even the most basic cyber secuirty operations can be overwhelming for non technical or 
inexperienced audiences. The purpose of Npen is to act as a user friendly interface enabling
users to conduct vulnerability scans on local networks or individual machines with very little
to no human interaction or prior knowledge required. 

To utilise the application follow the following instructions:

1. After installation open a terminal and navigate to the Npen directory.
2. Next, enter the command 'sudo python Pen_Testing_App.py'
3. Assuming everything has gone to plan you should be at the main menu,
   if you dont know which option to choose select option '3' and sit back
   while a vulnerability report is generated for you as Npen assesses the
   security posture of your network.

Npen conducts vulnerability scans through the use of Nmap commands, a popular open source
network scanning software. The information found by Npen is then used in tandem with the
'vulners' NSE script which cross references the port data found of each node with the public
vulnerability database API via Vulners.com. Finally an exevutive summary will be displayed 
through the terminal disclosing if any nodes are vulnerable. Further information regarding
any identified vulnerabilities and the nature of the scan for that matter can be located 
within the technical report. The location of the report should be within in then Npen directory. 

