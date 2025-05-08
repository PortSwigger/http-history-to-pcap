# BurpHistory2Pcap

A [burp2pcap](https://github.com/turekt/burp2pcap) script implemented as a Burp extension.
BurpHistory2Pcap exports selected traffic directly from Burp HTTP History tab into a PCAP file.

## Requirements

To generate a PCAP file with this extension, <ins>libpcap must be installed</ins> on the system.

## Build

Requirements to build the extension:
- JDK 21+
- Gradle or Maven

### Build using Gradle

Gradle build command:
```
gradle jar
```
Import `burphistory2pcap.jar` file located in `build/libs` folder to Burp suite.

### Build using Maven

Maven build command:
```
mvn package
```
Import `burphistory2pcap-1.0.0.jar` file located in `target` folder to Burp suite.

## Usage

In HTTP History tab under Proxy, select rows that you want to export (Ctrl + A to select all) and then right click to open context menu. Under context menu choose:
```
Extensions -> BurpHistory2Pcap -> Export selected HTTP message(s) to PCAP
```

Specify write options:
- Filepath
  - local path where the PCAP file will be saved
- Use port 80
  - if checked sets the server port in the PCAP file to HTTP 80 which significantly improves Wireshark packet dissection
  - uncheck if you want to have actual server port in your PCAP file
- Use real server IPs
  - if checked PCAP file will contain real server IP addresses, otherwise server IP will be set to predefined local IP

The extension will generate a PCAP file containing selected HTTP messages on the specified filepath with set options.
