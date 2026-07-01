
# 🕵️‍♂️ Incident Report: NetSupport Manager RAT Detection

## 🛑 Executive Summary
On **2026-02-28 at 19:55 UTC**, multiple signature hits for the **NetSupport Manager RAT** (Remote Access Trojan) were detected in the SIEM logs. The malicious traffic originated from an internal Windows client connecting to the known malicious IP address **`45.131.214.85`** over **TCP port 443**. This report details the forensic investigation conducted on the network packet capture (PCAP) to isolate and identify the compromised asset.

---

## 🌐 Environment Baseline

To understand the scope of the investigation, here are the network characteristics provided:

| Attribute | Value / Scope |
| :--- | :--- |
| **Domain Name** | `easyas123.tech` |
| **Active Directory Domain Controller** | `10.2.28.2` (EASYAS123-DC) |
| **LAN Segment Range** | `10.2.28.0/24` |
| **LAN Gateway** | `10.2.28.1` |
| **Broadcast Address** | `10.2.28.255` |

---

## 🎯 Investigation Objectives & Findings

The analysis successfully answered the following standard incident response questions:

| Investigation Question | Evidence / Answer |
| :--- | :--- |
| **1. What is the IP address of the infected client?** | `[Insert_Infected_IP_Here]` |
| **2. What is the MAC address of the infected client?** | `[Insert_MAC_Address_Here]` |
| **3. What is the host name of the infected client?** | `[Insert_Host_Name_Here]` |
| **4. What is the user account name?** | `[Insert_Username_Here]` |
| **5. What is the full name of the user?** | `[Insert_Full_Name_Here]` |

---

## 🔍 Forensic Analysis & Wireshark Methodology

### Step 1: Identifying the Infected Internal Host
To isolate the local host communicating with the malicious Command and Control (C2) server, apply the following filter:
```text
ip.addr == 45.131.214.85 and tcp.port == 443
