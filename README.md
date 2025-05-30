# MicroC2 Framework - Academic Research Project

**MicroC2 is a fork of the MicroC2 framework, building upon the original bachelor's thesis to provide improved functionality, front-end, OPSEC capabilities, and stability.**

**This thesis proposes the design of a lightweight C2 framework for penetration testing and red team operations, emphasizing stealth and a low system footprint. The framework utilizes covert communication, encryption and obfuscation to evade detection by security tools like EDR and IDS. Its effectiveness is evaluated in simulated environments, offering insights into evasion techniques and improving defensive strategies.**


## 🚨 ETHICAL DISCLAIMER AND LEGAL NOTICE

**This software is for academic research, cybersecurity education, and authorized defensive security testing ONLY. Unauthorized, malicious, or illegal use is strictly prohibited and may lead to severe legal consequences.**

This research, supervised by the **Cyber-Defence Campus Switzerland**, adheres to responsible research principles, institutional ethics, and relevant guidelines. **All development and testing occurred in isolated, controlled lab environments.**

**Permitted Uses:**
- Academic research and education.
- Authorized penetration testing (with explicit written permission).
- Authorized red team exercises.
- Defensive cybersecurity R&D.
- Supervised student learning.

**Prohibited Uses:**
- Unauthorized system/network access.
- Deployment without explicit permission.
- Malicious activities or cybercrime.
- Commercial exploitation without license.
- Distribution without this notice.

**User Responsibilities:**
By using this software, you agree to:
1. Comply with all applicable laws.
2. Use for authorized, legal, and ethical purposes only.
3. Understand its dual-use nature.
4. Maintain these guidelines in derivative works.
5. Report vulnerabilities responsibly.

---

## ⚠️ Known Limitations and Security Considerations

Developed under academic constraints (timeline, research focus, lab testing), this framework prioritizes proof-of-concept over production-ready security.

**Key Limitations:**
- Incomplete input validation.
- Basic error handling.
- Research-grade cryptographic implementations.
- Functionality-focused network security (not hardened).
- Basic authentication.
- Limited operational logging/monitoring.

**For Authorized Testing:**
- Use ONLY in isolated, air-gapped environments.
- Implement robust monitoring and logging.
- Secure explicit written authorization.
- Adhere to institutional research protocols.
- Coordinate with network/security teams.

---

## 🛡️ Defensive Research Applications

This framework can be used to:
- **Develop Detection Signatures**: Analyze C2 communication patterns for defensive purposes
- **Improve Security Monitoring**: Understand evasion techniques to enhance detection capabilities
- **Train Security Professionals**: Provide hands-on experience in controlled environments
- **Academic Research**: Support thesis work and cybersecurity education

---

## 🔧 Technical Documentation

---

## 🏗️ Architecture Overview

### Server (Go)
- **RESTful API**: Listener management, agent communication, file operations
- **WebSocket Endpoints**: Real-time logging and shell access
- **TLS Support**: Encrypted communications with certificate generation
- **Modular Design**: Extensible protocol handlers and listener management

### Agent (Rust)
- **Adaptive OPSEC**: Dynamic operational mode adjustment based on threat scoring
- **Memory Protection**: In-memory encryption of sensitive state data
- **Anti-Analysis**: String obfuscation, process monitoring, sandbox evasion
- **Network Flexibility**: HTTP(S) polling, SOCKS5 proxy support, reverse tunneling

### Web Interface
- **Dashboard**: Real-time agent status and system monitoring
- **Listener Management**: HTTP(S) and SOCKS5 listener configuration
- **Payload Generation**: Cross-platform agent compilation with custom configuration
- **File Operations**: Secure upload/download functionality

---

## ✨ Key Features

- **Adaptive OPSEC Engine**: Dynamic behavioral adjustment based on environmental threat assessment
- **Memory Protection**: AES-256-GCM encryption of sensitive state with immediate zeroization
- **Platform-Specific Evasion**: Windows API hiding and Linux session detection mechanisms
- **SOCKS5 Proxy Pivoting**: Multi-hop network traversal with reverse tunneling capabilities
- **Minimal Footprint**: Optimized Rust agent with aggressive size reduction and anti-analysis features
- **Modular Architecture**: Extensible framework supporting multiple communication protocols

---

## Getting Started

### Prerequisites
- **Go** (v1.23+ recommended)
- **Rust** (for agent builds)
- **Node.js & npm** (for web UI development, if you plan to modify frontend)
- **Git** (to clone the repository)
- **MinGW-w64** (for cross-compiling Windows agents from Linux)

### Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/Darkroom4364/MicroC2.git
   cd MicroC2
   ```
2. **Build the server:**cd 
   ```sh
   cd server
   go build -o server ./cmd/server.go
   ```
3. **Build the agent (optionally use cargo strip to reduce compile build as much as possible):**
   ```sh
   cd ../agent
   cargo build --release
   ```
4. **Build the agent for Windows (from Linux):**
   - Install MinGW-w64:
     ```sh
     sudo apt-get update && sudo apt-get install mingw-w64
     ```
   - Ensure the import library for Iphlpapi is available and symlinked:
     ```sh
     sudo ln -sf /usr/x86_64-w64-mingw32/lib/libiphlpapi.a /usr/x86_64-w64-mingw32/lib/libIphlpapi.a
     ```

### Running the Server
1. **Start the server:**
   ```sh
   cd server
   ./server
   ```
2. **Access the web interface:**
   - Open your browser and go to: [https://localhost:8080/home/](https://localhost:8080/home/) (or the port you configured).

### Configuration
- Edit `server/config/settings.yaml` for server settings.
- Edit `agent/src/config.rs` or use environment variables for agent configuration.

### TLS certificates for using HTTPS
- Run the following in MicroC2/server/ to generate TLS certificates
    ```
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
    ```

### Creating Listeners
- Use the web UI to create HTTP Polling or SOCKS5 listeners.
- Agents will connect to the listener endpoints you configure.

### Building Payloads
- Use the Payload Generator in the web UI to generate agent binaries for your target OS/architecture.

### File Drop
- Upload and download files via the File Drop section in the web UI. Folder in codebase is /server/uploads/

## SOCKS5 Proxy Pivoting Setup (Multi-Hop Example)

MicroC2 supports SOCKS5 proxy pivoting, including multi-hop scenarios. Below is a tested workflow for chaining agents and listeners to pivot through multiple internal hosts.

### Topology Example

```
Client <-> Server <-> VM1 <-> VM2
```

- **Server**: Runs MicroC2 server and first agent (pivot entry point)
- **VM1**: First virtual machine, runs agent and acts as a SOCKS5 pivot server and uses a socks reverse proxy to connect to the c2 server
- **VM2**: second virtual machine, runs second agent

---

### Step-by-Step Workflow

#### 1. **Set Up Two SOCKS5 Listeners**

- In the MicroC2 web UI, create two SOCKS5 listeners (everything apart from URI setup is free to be configured): 
  - **Listener 1**: For the agent on VM1 (e.g., port 8443)
  - **Listener 2**: For the agent on VM2 (e.g., port 8444)

#### 2. **Deploy and Configure Agents**

- **On VM1:**
  - Build an agent payload in the web UI, enabling SOCKS5 configuration.
  - Set the SOCKS5 proxy host/port to point to the MicroC2 server and Listener 1.
  - Deploy and run the agent on VM1.
  - Start the SOCKS5 pivot on VM1:
    ```sh
    pivot_start 1080
    ```
  - (Optional) Start SSH if needed for port forwarding on c2 server and pivot server:
    ```sh
    sudo systemctl start ssh
    ```
  - and connect on the agent side with
    ```sh
    ssh -N -D SOCKS5_PROXY_PORT ServerUsername@ServerIP
    ```

- **On VM2:**
  - Build a second agent payload, configuring it to use VM1 as its SOCKS5 proxy (host: 127.0.0.1, port: 1080).
  - Deploy and run the agent on VM2.
  - Start the SOCKS5 pivot on VM2:
    ```sh
    pivot_start 1081
    ```
  - SSH from VM2 to VM1 if needed:
    ```sh
    ssh -N -D VM1_PROXY_PORT Vm1Username@IPofVm1
    ```

---

## 📄 License and Academic Use

**This project is released under BSD-3-Clause with Non-Commercial Restriction for academic and research purposes only.**

---

**Remember: With great power comes great responsibility. Use this knowledge to build a more secure digital world.**
