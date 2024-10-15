# Beaconfuzz — A Wi-Fi fuzzing tool using only beacon frames

## Overview
**Beaconfuzz** is a lightweight multi-faceted tool designed to perform 802.11 beacon fuzzing. It includes
* an injection module that enables user to craft and inject malformed beacon frames
* a monitor module which is capable of putting the WNIC into monitor mode to sniff 802.11 frames by hopping across different channels

Supports three modes: Send, Monitor and Combined
* **Send Mode:** Crafts and sends beacons based on the parameters specified in a single
user-defined config.ini file
* **Monitor Mode:** Monitors 802.11 management frames and writes the frame info to stdout
or to a csv file
* **Combined Mode:** Sends and monitors simultaneously for capturing device responses and evaluation of the injection impact

## Prerequisites
### Python Dependencies
[![Python](https://img.shields.io/badge/Python-3.10.2-green)](https://www.python.org/downloads/) [![Scapy](https://img.shields.io/badge/Scapy-2.5.0-green)](https://pypi.org/project/scapy/) [![pycountry](https://img.shields.io/badge/pycountry-23.12.11-green)](https://pypi.org/project/pycountry/) [![rich](https://img.shields.io/badge/rich-13.7.1-green)](https://pypi.org/project/rich/)

### Package Dependencies
![wireless-tools](https://img.shields.io/badge/wireless--tools-blue) ![aircrack-ng](https://img.shields.io/badge/aircrack--ng-blue) ![iw](https://img.shields.io/badge/iw-blue)

### Hardware Requirements
A WNIC that supports monitor mode

## Usage
```
beaconfuzz [-h] -m <execution mode> -i <interface> [-t <timeout>] [-d <dwell time>]
[-c <channel1> [<channel2> <channel3> ...]] [-b <bandwidth>] [-p <config ini path>]
[-o <output>] [-f <filter> [<param1> <param2> ...]]

options:
  -h, --help            show the help message and exit
  -m <execution mode>   execution mode {send,monitor,combined} (default: send)
  -i <interface>        Wi-Fi interface
  -t <timeout>          timeout in seconds (default: 50)
  -d <dwell time>       dwell time in seconds (default: 0.7)
  -c <channel1> [<channel2> <channel3> ...]
                        channel number, can be provided multiple times (default: 6)
  -b <bandwidth>        channel bandwidth in MHz (default: None)
  -p <config ini path>  path to config file (default: None)
  -o <output>           output path for monitoring results, either 'stdout' or 'table' or
                        '<file name>.csv' (default: stdout)
  -f <filter> [<param1> <param2> ...]
                        filter* for monitor mode, can be provided multiple times
                        (default: None)

  *Available filter functions:
    1. subtype_filter(*subtypes: str): filters all frames with the given subtypes
    2. ssid_filter(*ssids: str): filters all frames with the given SSIDs
    3. mac_filter(mac_type: str, mac: str): filters all frames with the MAC
        address 'mac' wrt. 'mac_type' {addr1, addr2, addr3, addr4}
```

1. Make sure to install all the dependencies:
```sh
$ sudo apt update && sudo apt install -y wireless-tools aircrack-ng iw
$ pip install -r requirements.txt
```
2. Use the Makefile to generate the executable **beaconfuzz**
3. Specify the wireless interface to be put into monitor mode via interface *-i* option
4. Set the execution mode via mode *-m* option
5. * If the mode is *send*:
        - Create a configuration *.ini* file specifying the beacon frame structure
        and sending parameters
        - Give the path to the configuration file via path *-p* option
   * If the mode is *monitor*:
        - Choose one of the provided filter functions to filter the desired management
        frames via filter *-f* option, if necessary
        - Set the output path for monitoring results via output *-o* option
   * If the mode is *combined*, the options above for both *send* and *monitor*
     modes are provided
6. For all the execution modes,
   * Set the timeout indicating the execution duration via timeout *-t* option
   * Set the Wi-Fi channel to operate on via channel *-c* option
   * Set the channel bandwidth via bandwidth *-b* option
   * Provide the dwell time to stay on each channel via dwell *-d* option

## Configuration File Format
An INI file that includes all the settings for the beacon frame to be send and other injection parameters. An example configuration file is presented below and can also be found in the repository:
```
# beaconfuzz/configs.ini

# MAC Header section including 802.11 MAC Header fields
[MAC Header]
# Destination MAC address, by default broadcast MAC
DA = 11:11:11:11:11:11
# Source MAC address
SA = 22:22:22:22:22:22
# Basic Service Set ID
BSSID = 22:22:22:22:22:22
# Fragment Offset
FOffset = 15
# Sequence Number
SNumber = 0XFF3

# Mandatory Beacon Body
[Beacon Body]
# Timestamp
Timestamp = 124435
# Beacon Interval in TUs
Interval = 100
# Capability Information
Capability = privacy
# Service Set ID
SSID = TESTEST
# Supported Rates
Rates = 12, 18, 24, 36, 48, 72, 96, 108

# A number of optional Information Elements (IEs)
[Beacon Ext]
# FH Parameter Set IE: Dwell Time, Hop Set, Hop Pattern, Hop Index
FHSet = 500, 1, 2, 0
# DS Parameter Set IE: Current Channel
DSSet = 6
# CF Set IE: Count, Period, Max Duration in TUs, Duration Remaining in TUs
CFSet = 1, 2, 500, 0
# IBSS IE: ATIM Window
IBSS = 0
# TIM IE: Count, Period, Bitmap Control, Partial Virtual Bitmap
TIM = 2, 1, 0, 0x12003
# Country IE with Country Constraint Triple(s): Country Code, [First Channel Number; Number of Channels; Maximum Transmit Power]...
Country = DE, [1; 13; 20], [6; 5; 11]
# Power Constraint IE: Local Power Constraint
PConstraint = 30
# Channel Switch Announcement IE: Mode, New Channel Number, Count
CSA = 0, 11, 1
# Quiet IE: Count, Period, Duration, Offset
Quiet = 1, 2, 100, 0
# TPC Report IE: Transmit Power, Link Margin
TPCReport = 20, 0
# ERP IE in hex string
ERP = 0x00
# Extended Rates IE
ERates = 2, 4, 11, 22

# RSN Information Element, also part of Beacon Ext
[RSN Info]
# RSN Version
Version = 1
# Group Cipher Suite
GroupCS = 0x000fac04
# Pairwise Cipher Suite Count
PairwiseCSC = 2
# Pairwise Cipher Suite
PairwiseCS = 0x000fac04, 0x000fac05
# Authentication Suite Count
AKMCSC = 2
# Authentication Suite
AKMCS = 0x000fac02, 0x01020a0b
# RSN Capabilities
RSNCaps = 0x0000
# Pairwise Master Key Count
PMKC = 3
# Pairwise Master Key List
PMKL = 0x00ca, 0x123456789a, 0xffffff

# Other injection parameters
[Packet Send]
# Actual interval in seconds between consecutive beacon transmissions
inter = 0.1
# Number of beacons to be sent
count = 10
```
