# HTTPS-Decryption-And-Analysis-Wireshark

In this I have decrypted HTTPS traffic secured with a TLS certificate to identify the type of malware that infected a system on the network. 
The Resources include a pcap file containing encrypted traffic, SSL encryption keys and VirusTotal Reports.

## Setup and Environment
### Prerequisites
- Install Wireshark on your system.
- Download the Material zip file from the repository.
- Extract the files to your preferred location.

### Procedure
1. Open Wireshark and load the provided pcap file.
2. Configure Wireshark preferences for TLS decryption using the supplied SSL encryption key.
3. Apply filters to identify TLS handshakes and decrypt the traffic.
4. Analyze HTTP requests, identify malicious activities, and decrypt specific content.
5. Export malicious objects, such as DLL files, for further analysis on VirusTotal.


## Repository Structure
- **Material:** Contains the pcap file, SSL encryption keys, and other necessary files.
- **Documentation:** Detailed documentation, including step-by-step guides and technical explanations.
- **Screenshots:** Demonstrations for each step of the analysis process.

