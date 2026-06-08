# 🛡️ ProcSentinel v1.0 - Lightweight EDR Agent for Linux
## 📖 Description

ProcSentinel is a lightweight, low-CPU, open-source Endpoint Detection & Response (EDR) agent for Linux. It monitors running processes and network sockets in real-time to detect anomalous activities and potential threats.

The agent leverages the built-in D-Bus architecture to bridge the gap between root-level execution and the user space, sending native desktop notifications upon detecting suspicious behavior. It is designed around a single core engine that can be executed either as a highly readable Command-Line Interface (CLI) tool or a modern PyQt6-based cybersecurity Dashboard (GUI).

**Core Features:**
* **O(1) State Management:** Optimizes `psutil` queries and minimizes CPU/RAM overhead by utilizing a Set-based state management system. It only filters and processes newly spawned or modified processes.
* **Reverse Shell Detection:** Actively monitors network sockets. Outbound TCP connections to known suspicious ports (e.g., 4444, 1337, 9001) are immediately intercepted and flagged as **🚨 CRITICAL**.
* **Malicious Directory Scanning (Anomaly Detection):** Processes executing from temporary or volatile directories heavily targeted by attackers (such as `/tmp`, `/dev/shm`) are tagged as **⚠️ ANOMALY**.
* **Smart D-Bus Notification Bridge:** Runs securely with root privileges while tunneling alerts to the user's X11/Wayland desktop environment. Critical alerts remain persistent on the screen, whereas anomaly alerts dismiss automatically.
* **Standalone Linux Binary:** Can be easily compiled into a single executable binary, packaging all Python dependencies for seamless deployment across Linux environments.

---

# Usage
Due to the deep system-level process and network socket inspection, the agent **must** be executed with **`sudo` (root)** privileges.
### 1. CLI Mode 
To launch the lightweight, log-based monitoring engine in the terminal:
``` bash
sudo uv run procsentinel.py
```
### 2. GUI Mode 
To launch the modern, PyQt6-based monitoring dashboard:
``` bash
sudo uv run procsentinel.py -ui
```
(You can safely exit the interface at any time using the Ctrl+Q shortcut).

---

## 🤝 Support & Contact

Thank you for taking the time to review the code! This project was developed as an engineering study focusing on Linux system architecture and cybersecurity threat hunting.

**How you can help:**
* ⭐ **Star the repo** if you find it useful or learned something new.
* 🐛 **Open an Issue** to report bugs or suggest features.
* 🛠️ **Submit a Pull Request (PR)** if you want to add new detection rules or improve the core engine.

**License:** This project is fully open-source and protected under the **GPL-3.0** license. You are completely free to fork, study, and contribute.

**Contact:**
* **LinkedIn:** [Mümin Kayaaslan] (https://www.linkedin.com/in/m%C3%BCmin-kayaaslan-173923256/)
* **Instagram:** [CoderMuminn](https://www.instagram.com/codermuminn/?igsh=MXZpNWQ5bDg2ZHExag%3D%3D#)