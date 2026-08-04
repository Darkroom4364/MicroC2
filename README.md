# MicroC2 Framework - Academic Research Project

## 📚 Project Background and Development Context

**This framework was developed as part of a bachelor's thesis conducted at the [Cyber Defence Campus](https://www.cydcampus.admin.ch/en) in collaboration with [ETH Zurich](https://ethz.ch/en.html). The project serves as a research testbed for exploring the limitations and detection capabilities of state-of-the-art AV and EDR solutions.**

(I do however plan on continuing developement on this as it has become a passion project. Goal is to build this into a fully fleshed out research testbed)

### ⚠️ Development Acknowledgments

**Ths project was developed under a rather compressed timeline, prioritizing research validation over production readiness.** Please expect:

- **Prototype-Grade Code**: Some design decisions may require refinement
- **Implementation Gaps**: Certain features contain placeholder implementations
- **Limited Testing**: Comprehensive testing was constrained by timeline
- **Potential Bugs**: Rapid development may have introduced edge cases


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
- Lab-oriented operator authentication without multi-user roles.
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

- [Architecture](docs/architecture.md)
- [Design notes](docs/design.md)
- [Authenticated agent enrollment](docs/agent-enrollment.md)
- [Durable storage, recovery, and backup](docs/storage.md)
- [Roadmap](docs/roadmap.md)
- [Development workflow and CI](docs/development-workflow.md)
- [Health, readiness, and runtime telemetry](docs/health-telemetry.md)

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
- **Network Flexibility**: HTTP(S) polling with optional outbound SOCKS5 proxying

### Web Interface
- **Dashboard**: Real-time agent status and system monitoring
- **Listener Management**: HTTP(S) polling listener configuration
- **Payload Generation**: Cross-platform agent compilation with custom configuration
- **File Operations**: Secure upload/download functionality

---

## ✨ Key Features

- **Adaptive OPSEC Engine**: Dynamic behavioral adjustment based on environmental threat assessment
- **Memory Protection**: AES-256-GCM encryption of sensitive state with immediate zeroization
- **Platform-Specific Evasion**: Windows API hiding and Linux session detection mechanisms
- **SOCKS5 Egress**: Optional outbound proxying for agent HTTP(S) traffic
- **Minimal Footprint**: Optimized Rust agent with aggressive size reduction and anti-analysis features
- **Modular Architecture**: Extensible framework supporting multiple communication protocols

---

### 🐛 **Bug Reports Welcome (Seriously, Please Help!)**

**Found something broken? Congratulations, you're probably right!** 

This framework was built by someone running on way too much caffeine. If you encounter:
- Mysterious crashes that make no sense
- Features that work "sometimes" 
- Error messages that are less helpful than a chocolate teapot
- Code that makes you go "wait, how does this even compile?"

**Please report them!**

**Bonus points if you can explain why something is broken in simpler terms than I used to break it!**

---

## Getting Started

### Automatic installation using the install script
    ```sh
    chmod +x ./MicroC2/install.sh
    ./install.sh
    ```

### Manual Installation
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
2. **Build the server:**
   ```sh
   cd server
   go build -o server ./cmd
   ```
3. **Compile-check the agent source:**
   ```sh
   cd ../agent
   cargo build --locked --release
   ```
   This direct Cargo artifact intentionally has no listener identity or
   enrollment credential and is not deployable. After starting the server,
   create a listener and use the Payload page to generate a validated Linux
   x64 ELF or Windows x64 EXE payload.
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
   - Open your browser and go to: [https://localhost:8443/home/](https://localhost:8443/home/) with the default config. Port `8080` redirects to HTTPS when redirects are enabled.
   - The operator UI/API and WebSocket routes live on the web/API port. Agent polling routes live on the listener ports you create.

### Configuration
- Edit `server/config/settings.yaml` for server settings.
- The operator server is always HTTPS. `server.port` is its sole HTTPS port;
  `server.tls.certFile` and `server.tls.keyFile` are mandatory. When
  `server.redirect.enabled` is true, `server.redirect.httpPort` serves only the
  HTTP-to-HTTPS redirect. It must be empty when redirects are disabled. Keep
  both TLS files outside `server.staticDir`; HTTPS agent listeners inherit
  these paths unless their API configuration supplies an explicit certificate
  and key override.
- `server.uploadDir`, `server.staticDir`, and `logging.file` select the
  operator upload root, static root, and log file. Unknown or retired YAML
  fields are rejected instead of ignored.
- Browser-origin entries must be `"*"` or exact HTTP(S) origins without paths;
  allow-list matching includes scheme, host, and effective port.
- Durable server state defaults to `server/data/microc2.db` when the server is
  launched from `server/`. Keep `storage.path` outside `server.staticDir`; use
  `MICROC2_STORAGE_PATH` for an environment-specific override. See
  [Durable storage, recovery, and backup](docs/storage.md).
- Generate agent configuration through the payload builder. Direct custom
  builds use the documented build environment, including a fresh
  `ENROLLMENT_CREDENTIAL`; do not commit or log that value.

### Safe lab defaults

- With `security.operatorToken` empty, the operator UI, API, file drop, and log
  stream accept loopback clients only. This keeps the default local workflow
  available without exposing operator control to the lab network.
- The host-shell WebSocket is disabled by default. Set
  `security.enableServerTerminal: true` only for a controlled lab that needs
  it. Access requests and session open/close state are audited even when access
  is denied; commands and terminal output are never recorded as audit fields.
- For remote operator access, set a strong token through the environment
  instead of committing it to YAML:

  ```sh
  MICROC2_OPERATOR_TOKEN='<random-lab-secret>' ./server
  ```

  Remote API clients must send that value in `X-Operator-Token`. Cross-origin
  browser origins must also appear in `security.operatorAllowedOrigins`;
  exact same-origin browser requests are allowed automatically.
- Agent-listener CORS is limited by `security.corsOrigins`. An empty list
  disables cross-origin browser access; `"*"` is an explicit unsafe escape
  hatch and should not be used for normal lab runs.
- Production agent listeners and payload builds require HTTPS with normal
  certificate validation. Plain HTTP is rejected unless
  `security.agentTransport.allowInsecureIsolatedLab` is explicitly enabled for
  an isolated lab.
- Generated payloads always use the system trust store; the payload API does
  not expose an invalid-certificate option. A manual custom build may set
  `ALLOW_INVALID_CERTS=true` only together with
  `ALLOW_INSECURE_ISOLATED_LAB=true`. These are contained-lab escape hatches,
  not deployment defaults. `requireClientCert` is rejected until MicroC2 has
  CA-backed mTLS verification.
- Agent lifecycle routes use listener-, payload-, and runtime-bound enrollment
  credentials added by #104. See
  [Authenticated agent enrollment](docs/agent-enrollment.md) for rotation,
  recovery, and upgrade details.
- Structured audit history is available to authenticated operators at
  `GET /api/audit/events?limit=50&offset=0`. It is durable and redacted but
  still contains sensitive object metadata; see
  [audit retention and redaction](docs/storage.md#structured-audit-events).
- Bind listeners only to the isolated lab segment and keep detonation VMs
  without direct internet egress. See
  [`docs/research/r1-measurement-protocol.md`](docs/research/r1-measurement-protocol.md)
  before executing measurement cells.

### TLS certificates for using HTTPS
- Prefer a certificate trusted by the agent's system trust store. For a
  contained localhost lab, the following command creates a self-signed
  certificate in `MicroC2/server/`. Install that certificate (or its lab CA) in
  the agent machine's trust store before using it with a generated payload.

  ```sh
  mkdir certs && openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  ```

- If installing a lab trust anchor is impractical, explicitly enable
  `security.agentTransport.allowInsecureIsolatedLab` and use plain HTTP only on
  the contained lab network. Do not weaken certificate validation on ordinary
  generated payloads.

### Creating Listeners
- Use the web UI to create HTTPS polling listeners. Plain HTTP polling requires
  the explicit isolated-lab transport override.
- A listener may set one advertised DNS name or IP for generated payloads. It
  may be omitted only when the bind host itself is a specific, advertiseable
  address; wildcard bind addresses require the advertised host. Host rotation,
  custom listener headers/URIs/user-agents, listener-side proxies,
  DNS-over-HTTPS, and SOCKS5 listener mode are not implemented and are rejected
  if submitted through the API.
- Agents will connect to the listener endpoints you configure.

### Building Payloads
- Use the Payload Generator in the web UI to generate agent binaries for your
  target OS/architecture. The exact supported profiles, validation rules,
  deterministic output path, manifest API, and download integrity headers are
  documented in [Payload build contract](docs/payload-builds.md).
- Each production build receives a new secret enrollment input; source
  revision and mutation seed reproduce mutation choices, but do not recreate a
  byte-identical credential-bearing artifact.

### File Drop
- Upload and download files via the File Drop section in the web UI. Folder in codebase is /server/uploads/

## SOCKS5 Egress

The payload builder can configure the agent's HTTP client to use an existing
SOCKS5 proxy. This is outbound proxy configuration only. MicroC2 does not yet
provide a supported SOCKS5 listener or multi-hop pivot workflow; the remaining
pivot modules are prototype code tracked on the roadmap.

## 📄 License and Academic Use

**This project is released under BSD-3-Clause with Non-Commercial Restriction for academic and research purposes only.**

---

**Remember: With great power comes great responsibility. Use this knowledge to build a more secure digital world.**
