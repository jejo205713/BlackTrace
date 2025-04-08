# 🛡️ BlackTrace - Stealth Backdoor Hunter for Linux

> “In the dark corners of your network, **BlackTrace** sees what others miss.”

**BlackTrace** is a lightweight, Python-based network inspection tool designed to detect and neutralize hidden backdoor connections on Linux systems. Inspired by offensive security tactics, BlackTrace scans your system's active network sessions for suspicious remote IPs and ports, flagging possible reverse shells, RATs, and malware persistence.

---

## 🔥 Features

- 🔍 Real-time scan of active TCP/UDP connections (`ss -tunap`)
- 🧠 Heuristic detection of suspicious remote IPs and rogue ports
- 🔐 Auto-blocks malicious IPs using `iptables`
- ⚡ Lightweight and easily scriptable
- 🕶️ Designed with a dark, stealthy hacker vibe

---

## ⚔️ Targets

BlackTrace is effective against:

- Reverse shells (e.g., Netcat, Bash, Metasploit)
- Foreign IP persistence connections
- Suspicious ports like `4444`, `1337`, `31337`, etc.
- Unauthorized outbound traffic

---

## 📷 Working

![Working](https://github.com/jejo205713/BlackTrace/blob/main/working.png)

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/jejo205713/BlackTrace.git
cd BlackTrace
```

### 2.Run the script :
```bash
sudo python3 blacktrace.py
```

---
## Credits:
```bash
Jejo J
```
