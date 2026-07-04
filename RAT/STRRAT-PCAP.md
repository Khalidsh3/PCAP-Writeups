# 🦠 Incident Report: STRRAT Malware Infection & Traffic Analysis

## 🛑 Executive Summary
On **Tuesday, July 30, 2024, at approximately 02:40 UTC**, an internal Windows host within the enterprise network was compromised by **STRRAT malware**. The attack sequence involved connections to external repositories to pull down malicious components, followed by persistent post-infection Command and Control (C2) beaconing. This incident report logs the investigation of the network packet capture (PCAP) to define the scope, isolate the victim asset, and document the key Indicators of Compromise (IoCs).

---

## 🌐 Environment Baseline

The network environment architecture contains the following boundaries:

| Attribute | Value / Scope |
| :--- | :--- |
| **Domain Name** | `wiresharkworkshop.online` |
| **Active Directory Domain Controller** | `172.16.1.4` (WIRESHARK-WS-DC) |
| **LAN Segment Range** | `172.16.1.0/24` |
| **LAN Gateway** | `172.16.1.1` |
| **Broadcast Address** | `172.16.1.255` |

---

## 🎯 Investigation Objectives & Findings

The forensic analysis successfully resolved the core incident response questions regarding the victim machine and threat profiling:

| Investigation Question | Evidence / Answer |
| :--- | :--- |
| **1. What is the IP address of the infected client?** | `172.16.1.66` |
| **2. What is the MAC address of the infected client?** | `00:1e:64:ec:f3:08` |
| **3. What is the host name of the infected client?** | `DESKTOP-SKBR25F` |
| **4. What is the user account name?** | `ccollier` |
| **5. What is the full name of the user?** | `Clark Collier` |
| **6. What data/activity was the malware doing?** | Checking the host's external IP via `ip-api.com` and initiating continuous, encrypted beaconing containing system profiling strings (`ping|STRRAT...`) back to a C2 server over port 12132. |

---

## 🔍 Forensic Analysis & Wireshark Methodology

### Step 1: Discovering the Malicious & Suspicious Traffic Links
To isolate suspicious connections bypassing standard baseline web protocols, a specialized connection-tracking filter was applied:
```text
(http.request or tls.handshake.type == 1 or tcp.flags.syn == 1 && tcp.flags.ack == 0) && !ssdp
```
As shown in the **image below**, this filter catches the infected host (`172.16.1.66`) pulling data from GitHub infrastructure and Apache Maven repositories (`repo1.maven.org`), alongside a direct external IP check to `ip-api.com` via an unencrypted `HTTP GET /json/` request. Crucially, it isolates an outbound TCP SYN handshake targeting an unusual remote port (**12132**).

*![image alt](https://github.com/Khalidsh3/PCAP-Writeups/blob/b4738ec5444475f7450119c7606273fd725fb7f8/images/RAT-images/image1.png)*

---

### Step 2: Resolving Host Name via NetBIOS Service
By filtering for NetBIOS Name Service (`nbns`) traffic, the exact host naming registration queries coming out of the workstation were analyzed. Frame 30 explicitly maps out the workstation source identity as **`DESKTOP-SKBR25F`**, as detailed in the **image below**.

**

---

### Step 3: Extracting the Active User Account and Full Name
To legally tie the compromise to an internal threat actor or human asset, Active Directory queries were analyzed:

* Filtering for user authentication reveals the account handle name as **`ccollier`**.
* By examining SAMR/LDAP directory parameters (`samr.samr_UserInfo21.full_name`), the exact identity database maps out the user's full name as **`Clark Collier`**, as verified in the **image below**.

*![image alt](https://github.com/Khalidsh3/PCAP-Writeups/blob/0988f949679f7b96579958754b4ae8c95ee1570e/images/RAT-images/image4.png)*

---

## 📡 Step 4: Dissecting the STRRAT Post-Infection C2 Beaconing

Following the TCP stream for the traffic targeting port **12132** (specifically TCP Stream 83) reveals clear, human-readable text logs belonging to the **STRRAT Command and Control** mechanism.

As captured in the **image below**, the malware maintains a persistent connection heartbeat by sending continuous `ping\|STRRAT...` status bursts. The strings explicitly leak the host configuration details, indicating a Windows 11 Pro 64-bit platform protected by Windows Defender, alongside its deployment signature (`1BE8292C`).

*![image alt](https://github.com/Khalidsh3/PCAP-Writeups/blob/0988f949679f7b96579958754b4ae8c95ee1570e/images/RAT-images/image2.png)*

---

## 🚨 Indicators of Compromise (IoCs)

### 💻 Network Connections (Infrastructure Logs)
* `141.98.10.69` over TCP port `12132` (Active STRRAT C2 Server Node)
* `208.95.112.1` over TCP port `80` (`ip-api.com` IP Reconnaissance)
* `github.com` / `objects.githubusercontent.com` over Port `443` (Suspicious Component Fetching)
* `repo1.maven.org` over Port `443` (Dependency Repository Abuse)

---

## 🛠️ Remediation Blueprints

1. **Network Disconnect:** Instantly drop the physical or wireless connection of host `172.16.1.66` from the local gateway `172.16.1.1` to break the C2 beacon.
2. **Active Directory Threat Mitigation:** Flag and enforce an immediate credential reset on the `ccollier` (Clark Collier) user account.
3. **Forensic Reimaging:** Wipe out the disk drive of `DESKTOP-SKBR25F` to fully purge the local STRRAT persistent stagers.

