
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
| **1. What is the IP address of the infected client?** | `[10.2.28.88]` |
| **2. What is the MAC address of the infected client?** | `[00:19:d1:b2:4d:ad]` |
| **3. What is the host name of the infected client?** | `[DESKTOP-TEYQ2NR]` |
| **4. What is the user account name?** | `[brolf]` |
| **5. What is the full name of the user?** | `[Becka Rolf]` |

---

## 🔍 Forensic Analysis & Wireshark Methodology

### Step 1: Identifying the Infected Internal Host
Since the PCAP file retrive from a infected windows machine we can tell by that is the infected host is 10.2.28.88., OR we apply the following filter:
```text
(http.request or tls.handshake.type eq 1) and !(ssdp) and ip.addr eq 45.131.214.85
```
<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/88b6f189-efde-4cb1-90be-20faec159c19" />


---

### Step 2: extractin the MAC address :
We can use the filter "nbns" as always to find the windows host name and the MAC address as shown in the picture.
![image alt](https://github.com/Khalidsh3/PCAP-Writeups/blob/7b8668e9b6ec3b03d1be0a71973612af8b5d8eec/images/RAT-images/First-1.png)



