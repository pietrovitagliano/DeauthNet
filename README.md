# DeauthNet

## Disclaimer
This software can potentially be used for malicious and unethical purposes. Therefore, I, Pietro Vitagliano, the author of Deauth Net and owner of this repository, assume no responsibility for any improper or harmful use of this software. The tool has been developed exclusively for the ethical purposes described in my thesis, and any usage violating these principles is neither supported nor endorsed.

## Software Description
Deauth Net is a software designed and developed entirely by the owner of this repository, Pietro Vitagliano, as master’s thesis project in Computer Science at the University of Sannio in Benevento, within the scope of Security of Networks and Software Systems. It has been developed to perform deauthentication attacks, in order to demonstrate how easily such an attack can be executed and to provide tools for detecting and blocking this kind of attacks on the machine where the software is running, making it a comprehensive solution for evaluating and identifying deauthentication attacks on Wi-Fi networks.

## Credits
Deauth Net relies on the following python packages:
-	Scapy: Developed by Philippe Biondi, Scapy is a powerful Python library used for packet manipulation and network analysis.
-	Sortedcontainers: Created by Grant Jenks, this library provides fast and efficient sorted collections.
-	Rich: Developed by Will McGugan, Rich is a library for rendering rich text and advanced formatting in the terminal.

## Getting Started
### Dependencies
-	Linux
-	Python 3.10 or higher

#### Linux System Dependencies
-	net-tools
-	wireless-tools
-	ebtables-tools

To install these dependencies, execute the following commands in your terminal:

	sudo apt-get update
	sudo apt-get install -y net-tools wireless-tools ebtables

#### Python Packages
-	scapy >= 2.5.0
-	sortedcontainers >= 2.4.0
-	rich >= 13.7.1

To install these dependencies, from the project root directory, open your terminal and execute the following command:

	pip install -r requirements.txt

## Usage
### Initial Setup
Before utilizing any of the three primary functionalities, an initial scan of nearby access points must be conducted, that is the first functionality the software allows to perform. This scanning feature uses Scapy to detect nearby networks, which can then be targeted for attacks, or used for detection and blocking purposes.

### Main Features
Deauth Net provides three primary functionalities, besides the access point scan:
1.	Deauthentication Attack: This feature allows the execution of deauthentication attacks.
2.	Attack Detection: This feature detects deauthentication attacks using a sliding time window to monitor the number of deauthentication packets associated with a particular access point.
3.	Attack Blocking: An extension of the detection feature, this functionality not only detects but also blocks attacks by blacklisting the offending access point.

### Detection Mechanism
The detection mechanism relies on a time window to count the number of deauthentication packets associated with a specific access point within that window. Packets outside the window are discarded. If the number of packets exceeds a certain threshold, as defined in a project file, an attack is assumed to be in progress, and the detection functionality notifies the user.

### Blocking Mechanism
The blocking feature extends the detection functionality by adding the ability to blacklist an access point when an attack is detected.

## License
This software is released under the GPL-3 license, which allows for its use, modification, and distribution according to the terms of this license, requiring that any modifications made to the software must reference the original author.
