# DeauthNet

## Disclaimer
This software can potentially be used for malicious and unethical purposes. Therefore, I, Pietro Vitagliano, the author of DeauthNet and owner of this repository, assume no responsibility for any improper or harmful use of this software. This tool has been developed exclusively for ethical purposes and any usage that violates these principles is neither supported nor endorsed.

## Software Description
DeauthNet is a software designed and developed entirely by the owner of this repository, Pietro Vitagliano, as master’s thesis project in Computer Science at the University of Sannio in Benevento, within the scope of Security of Networks and Software Systems. It has been developed to perform de-authentication attacks, in order to demonstrate how easily such an attack can be executed and to provide tools for detecting and blocking this kind of attacks on the machine where the software is running, making it a comprehensive solution for evaluating and identifying de-authentication attacks on Wi-Fi networks.

## Credits
DeauthNet relies on the following python packages:
-	Scapy: Developed by Philippe Biondi, Scapy is a powerful Python library used for packet manipulation and network analysis.
-	Sortedcontainers: Created by Grant Jenks, this library provides fast and efficient sorted collections.
-	Rich: Developed by Will McGugan, Rich is a library for rendering rich text and advanced formatting in the terminal.

## Getting Started
### Dependencies
-	A Linux distribution (Ubuntu, Debian, etc)
-   A wireless network adapter that supports monitor mode (if the Linux distribution is running on a virtual machine, you need to use an external wireless network adapter)
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
Before utilizing any of the three primary functionalities, an initial scan of nearby access points must be conducted, facilitated through the software’s scanning feature utilizing Scapy. Users can customize the scanning process by modifying the /Core/WiFiBandManager/wifi_band_manager_settings.json file, that specifies the frequency bands to scan. This customization allows to scan for specific frequency bands, on which subsequently the attacking, detection and blocking functionalities of the software will focus. This approach ensures flexibility in evaluating and mitigating potential vulnerabilities across desired network frequencies.

### Main Features
DeauthNet provides three primary functionalities, besides the access point scan:
1.	De-authentication Attack: This feature allows the execution of de-authentication attacks.
2.	Attack Detection: This feature detects de-authentication attacks using a sliding time window to monitor the number of de-authentication packets associated with a particular access point.
3.	Attack Blocking: An extension of the detection feature, this functionality not only detects but also blocks attacks, by blacklisting the attacked access points.

### Attack Mechanism
The attack mechanism of DeauthNet is designed to disrupt network connectivity by forcing clients to disconnect from access points. When initiating an attack, user can select one or more access points, but DeauthNet also extends its impact to every access point within the same mesh network of the attacked ones, showing how easy is to affect an entire mesh network’s integrity. Once one or more target are chosen, the software continuously sends de-authentication packets across all associated frequencies, such as both 2.4 GHz and 5 GHz bands, simultaneously disrupting their connectivity. It’s crucial to emphasize that DeauthNet is intended for ethical purposes only, such as educational or research contexts and any unauthorized or malicious use of this tool is explicitly disclaimed and unsupported by the author.

### Detection Mechanism
The detection mechanism relies on a time window to count the number of de-authentication packets associated with a specific access point within that window. Packets outside the window are discarded. If the number of packets exceeds a certain threshold, as defined in a project file, an attack is assumed to be in progress, and the detection functionality notifies the user.

### Blocking Mechanism
The blocking feature extends the detection functionality by adding the ability to blacklist an access point when an attack is detected.

## License
This software is released under the GPL-3 license, which allows for its use, modification and distribution according to the terms of this license. In compliance with the GPL-3 license, any distribution or modification of this software must give credit to Pietro Vitagliano, the original author.
