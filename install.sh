#!/bin/bash
# MicroC2 Framework Installation & Update Script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"
AGENT_DIR="$SCRIPT_DIR/agent"
WEB_DIR="$SCRIPT_DIR/web"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${BLUE}"

echo "███╗   ███╗██╗ ██████╗██████╗  ██████╗  ██████╗██████╗ "
echo "████╗ ████║██║██╔════╝██╔══██╗██╔═══██╗██╔════╝╚════██╗"
echo "██╔████╔██║██║██║     ██████╔╝██║   ██║██║      █████╔╝"
echo "██║╚██╔╝██║██║██║     ██╔══██╗██║   ██║██║     ██╔═══╝ "
echo "██║ ╚═╝ ██║██║╚██████╗██║  ██║╚██████╔╝╚██████╗███████╗"
echo "╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝"
                                                       

    echo -e "${NC}"
    echo "MicroC2 Framework Installation & Update Script"
    echo "=============================================="
    echo
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get OS info
get_os_info() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to check if components are already built
check_existing_builds() {
    print_status "Checking existing builds..."
    
    local server_built=false
    local agent_built=false
    
    # Check server build
    if [ -f "$SERVER_DIR/server" ]; then
        if [ -x "$SERVER_DIR/server" ]; then
            print_success "Server binary found and executable"
            server_built=true
        else
            print_warning "Server binary found but not executable"
        fi
    else
        print_warning "Server binary not found"
    fi
    
    # Check agent build
    if [ -f "$AGENT_DIR/target/release/agent" ]; then
        if [ -x "$AGENT_DIR/target/release/agent" ]; then
            print_success "Agent binary found and executable"
            agent_built=true
        else
            print_warning "Agent binary found but not executable"
        fi
    else
        print_warning "Agent binary not found"
    fi
    
    # Check cross-compilation targets
    if [ -d "$AGENT_DIR/target/x86_64-pc-windows-gnu" ]; then
        print_success "Windows x64 target directory found"
    fi
    
    if [ -d "$AGENT_DIR/target/i686-pc-windows-gnu" ]; then
        print_success "Windows x86 target directory found"
    fi
    
    return $((server_built && agent_built))
}

# Function to check certificates status
check_certificates() {
    print_status "Checking TLS certificates..."
    
    if [ -f "$SERVER_DIR/certs/server.crt" ] && [ -f "$SERVER_DIR/certs/server.key" ]; then
        # Check certificate validity
        if openssl x509 -in "$SERVER_DIR/certs/server.crt" -noout -checkend 86400 >/dev/null 2>&1; then
            CERT_SUBJECT=$(openssl x509 -in "$SERVER_DIR/certs/server.crt" -noout -subject | sed 's/subject=//')
            CERT_EXPIRES=$(openssl x509 -in "$SERVER_DIR/certs/server.crt" -noout -enddate | sed 's/notAfter=//')
            print_success "Valid TLS certificates found"
            print_status "  Subject: $CERT_SUBJECT"
            print_status "  Expires: $CERT_EXPIRES"
        else
            print_warning "TLS certificates found but expired or invalid"
        fi
    else
        print_warning "TLS certificates not found"
    fi
}

# Function to check directories status
check_directories() {
    print_status "Checking directory structure..."
    
    local dirs=("static/listeners" "static/file_drop" "uploads" "config" "certs")
    local missing_dirs=()
    
    cd "$SERVER_DIR"
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            print_success "Directory exists: $dir"
        else
            missing_dirs+=("$dir")
            print_warning "Directory missing: $dir"
        fi
    done
    
    cd "$SCRIPT_DIR"
    
    if [ ${#missing_dirs[@]} -eq 0 ]; then
        print_success "All required directories exist"
        return 0
    else
        return 1
    fi
}

# Function to check configuration status
check_configuration() {
    print_status "Checking configuration files..."
    
    if [ -f "$SERVER_DIR/config/settings.yaml" ]; then
        print_success "Server configuration found"
        
        # Check if config file contains required sections
        if grep -q "server:" "$SERVER_DIR/config/settings.yaml" && \
           grep -q "tls:" "$SERVER_DIR/config/settings.yaml"; then
            print_success "Configuration appears valid"
        else
            print_warning "Configuration file exists but may be incomplete"
        fi
    else
        print_warning "Server configuration not found"
    fi
}

# Function to check Rust targets
check_rust_targets() {
    print_status "Checking Rust cross-compilation targets..."
    
    if command_exists rustup; then
        local targets=("x86_64-pc-windows-gnu" "i686-pc-windows-gnu" "aarch64-unknown-linux-gnu" "x86_64-unknown-linux-musl")
        local installed_targets
        installed_targets=$(rustup target list --installed)
        
        for target in "${targets[@]}"; do
            if echo "$installed_targets" | grep -q "$target"; then
                print_success "Rust target installed: $target"
            else
                print_warning "Rust target missing: $target"
            fi
        done
    else
        print_warning "Rustup not found, cannot check targets"
    fi
}

# Function to provide installation summary
show_installation_summary() {
    echo
    print_status "=== INSTALLATION SUMMARY ==="
    
    # Prerequisites summary
    echo
    print_status "Prerequisites:"
    command_exists go && print_success "✓ Go" || print_error "✗ Go"
    command_exists rustc && print_success "✓ Rust" || print_error "✗ Rust"
    command_exists git && print_success "✓ Git" || print_error "✗ Git"
    command_exists openssl && print_success "✓ OpenSSL" || print_error "✗ OpenSSL"
    command_exists x86_64-w64-mingw32-gcc && print_success "✓ MinGW-w64" || print_warning "✗ MinGW-w64 (optional)"
    
    # Components summary
    echo
    print_status "Components:"
    [ -f "$SERVER_DIR/server" ] && print_success "✓ Server binary" || print_warning "✗ Server binary"
    [ -f "$AGENT_DIR/target/release/agent" ] && print_success "✓ Agent binary" || print_warning "✗ Agent binary"
    
    # Infrastructure summary
    echo
    print_status "Infrastructure:"
    [ -f "$SERVER_DIR/certs/server.crt" ] && print_success "✓ TLS certificates" || print_warning "✗ TLS certificates"
    [ -f "$SERVER_DIR/config/settings.yaml" ] && print_success "✓ Configuration" || print_warning "✗ Configuration"
    [ -d "$SERVER_DIR/static" ] && print_success "✓ Directories" || print_warning "✗ Directories"
    
    echo
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    local missing_deps=()
    local needs_setup=()
    
    # Check Go
    if command_exists go; then
        GO_VERSION=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
        if [ -n "$GO_VERSION" ]; then
            if [[ "$(printf '%s\n' "1.23" "$GO_VERSION" | sort -V | head -n1)" == "1.23" ]]; then
                print_success "Go $GO_VERSION found (✓ meets requirements)"
            else
                print_warning "Go version $GO_VERSION found (⚠ 1.23+ recommended)"
            fi
        else
            print_error "Go found but version check failed"
        fi
    else
        missing_deps+=("go")
        print_error "Go not found (✗ required)"
    fi
    
    # Check Rust with better error handling
    if command_exists rustc && command_exists cargo; then
        # Check if rustup is available and configured
        if command_exists rustup; then
            # Check if default toolchain is set
            if rustup default 2>/dev/null | grep -q "default"; then
                RUST_VERSION=$(rustc --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
                if [ -n "$RUST_VERSION" ]; then
                    print_success "Rust $RUST_VERSION found (✓ installed)"
                else
                    print_warning "Rust found but version check failed"
                fi
            else
                print_warning "Rust installed but no default toolchain set"
                needs_setup+=("rust-default")
            fi
        else
            # Rust installed without rustup
            RUST_VERSION=$(rustc --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
            if [ -n "$RUST_VERSION" ]; then
                print_success "Rust $RUST_VERSION found (✓ installed, but rustup recommended)"
            else
                print_warning "Rust found but version check failed"
            fi
        fi
    else
        missing_deps+=("rust")
        print_error "Rust not found (✗ required)"
    fi
    
    # Check Git
    if command_exists git; then
        GIT_VERSION=$(git --version | grep -oP '\d+\.\d+\.\d+')
        print_success "Git $GIT_VERSION found (✓ installed)"
    else
        missing_deps+=("git")
        print_error "Git not found (✗ required)"
    fi
    
    # Check OpenSSL
    if command_exists openssl; then
        OPENSSL_VERSION=$(openssl version | grep -oP '\d+\.\d+\.\d+')
        print_success "OpenSSL $OPENSSL_VERSION found (✓ installed)"
    else
        missing_deps+=("openssl")
        print_error "OpenSSL not found (✗ required)"
    fi
    
    # Check Node.js (optional)
    if command_exists node && command_exists npm; then
        NODE_VERSION=$(node --version)
        print_success "Node.js $NODE_VERSION found (✓ optional)"
    else
        print_warning "Node.js not found (⚠ optional for web UI development)"
    fi
    
    # Check MinGW (optional)
    if command_exists x86_64-w64-mingw32-gcc; then
        MINGW_VERSION=$(x86_64-w64-mingw32-gcc --version | head -1 | grep -oP '\d+\.\d+\.\d+')
        print_success "MinGW-w64 $MINGW_VERSION found (✓ cross-compilation ready)"
    else
        print_warning "MinGW-w64 not found (⚠ needed for Windows cross-compilation)"
    fi
    
    # Handle setup issues
    if [ ${#needs_setup[@]} -ne 0 ]; then
        print_warning "Setup required for: ${needs_setup[*]}"
        echo
        for item in "${needs_setup[@]}"; do
            case $item in
                "rust-default")
                    print_status "To fix Rust default toolchain:"
                    echo "  rustup default stable"
                    echo "  # This will download and set the latest stable Rust as default"
                    ;;
            esac
        done
        echo
        print_status "Run the above commands and then re-run this script."
        echo
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_status "Please install missing dependencies and run the script again."
        
        # Provide installation hints based on OS
        OS=$(get_os_info)
        case $OS in
            "linux")
                echo
                print_status "Installation commands for Ubuntu/Debian:"
                echo "sudo apt update"
                echo "sudo apt install -y git openssl build-essential"
                if [[ " ${missing_deps[*]} " =~ " go " ]]; then
                    echo "wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz"
                    echo "sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz"
                    echo "echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.bashrc"
                fi
                if [[ " ${missing_deps[*]} " =~ " rust " ]]; then
                    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
                fi
                ;;
            "macos")
                print_status "Installation commands for macOS:"
                echo "brew install git openssl"
                if [[ " ${missing_deps[*]} " =~ " go " ]]; then
                    echo "brew install go"
                fi
                if [[ " ${missing_deps[*]} " =~ " rust " ]]; then
                    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
                fi
                ;;
        esac
        exit 1
    fi
    
    # Exit if setup is needed
    if [ ${#needs_setup[@]} -ne 0 ]; then
        exit 1
    fi
}

# Function to install MinGW for Windows cross-compilation
install_mingw() {
    print_status "Checking MinGW-w64 for Windows cross-compilation..."
    
    if command_exists x86_64-w64-mingw32-gcc; then
        print_success "MinGW-w64 already installed"
    else
        print_status "Installing MinGW-w64..."
        OS=$(get_os_info)
        case $OS in
            "linux")
                sudo apt-get update
                sudo apt-get install -y mingw-w64
                ;;
            "macos")
                if command_exists brew; then
                    brew install mingw-w64
                else
                    print_error "Homebrew not found. Please install MinGW-w64 manually."
                    exit 1
                fi
                ;;
            *)
                print_warning "MinGW installation not automated for this OS"
                ;;
        esac
        print_success "MinGW-w64 installed"
    fi
    
    # Create symlink for Iphlpapi library
    MINGW_LIB_PATH="/usr/x86_64-w64-mingw32/lib"
    if [ -f "$MINGW_LIB_PATH/libiphlpapi.a" ] && [ ! -f "$MINGW_LIB_PATH/libIphlpapi.a" ]; then
        print_status "Creating Iphlpapi library symlink..."
        sudo ln -sf "$MINGW_LIB_PATH/libiphlpapi.a" "$MINGW_LIB_PATH/libIphlpapi.a"
        print_success "Iphlpapi symlink created"
    fi
}

# Function to setup Rust targets with better error handling
setup_rust_targets() {
    print_status "Setting up Rust cross-compilation targets..."
    
    # Check if rustup is available
    if ! command_exists rustup; then
        print_warning "Rustup not found, skipping cross-compilation target setup"
        return
    fi
    
    # Check if default toolchain is set
    if ! rustup default 2>/dev/null | grep -q "default"; then
        print_warning "No default Rust toolchain set, skipping target setup"
        print_status "Run 'rustup default stable' first"
        return
    fi
    
    local targets=("x86_64-pc-windows-gnu" "i686-pc-windows-gnu" "aarch64-unknown-linux-gnu" "x86_64-unknown-linux-musl")
    
    for target in "${targets[@]}"; do
        print_status "Adding Rust target: $target"
        if rustup target add "$target" 2>/dev/null; then
            print_success "Target added: $target"
        else
            print_warning "Failed to add target: $target"
        fi
    done
    
    print_success "Rust targets configuration completed"
}

# Function to build server
build_server() {
    print_status "Building Go server..."
    
    cd "$SERVER_DIR"
    
    # Clean any previous builds
    if [ -f "server" ]; then
        rm server
    fi
    
    # Build the server
    go mod tidy
    go build -ldflags="-s -w" -o server ./cmd/server.go
    
    print_success "Server built successfully"
    cd "$SCRIPT_DIR"
}

# Function to build agent
build_agent() {
    print_status "Building Rust agent..."
    
    cd "$AGENT_DIR"
    
    # Clean previous builds
    cargo clean
    
    # Build release version
    cargo build --release
    
    # Strip binary to reduce size
    if command_exists strip; then
        strip target/release/agent
        print_success "Agent stripped for size optimization"
    fi
    
    print_success "Agent built successfully"
    cd "$SCRIPT_DIR"
}

# Function to generate TLS certificates
generate_certificates() {
    print_status "Generating TLS certificates..."
    
    cd "$SERVER_DIR"
    
    if [ ! -d "certs" ]; then
        mkdir certs
    fi
    
    if [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
        openssl req -x509 -newkey rsa:4096 \
            -keyout certs/server.key \
            -out certs/server.crt \
            -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        print_success "TLS certificates generated"
    else
        print_success "TLS certificates already exist"
    fi
    
    cd "$SCRIPT_DIR"
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    cd "$SERVER_DIR"
    
    # Create required directories
    mkdir -p static/listeners
    mkdir -p static/file_drop
    mkdir -p uploads
    mkdir -p config
    
    print_success "Directories created"
    cd "$SCRIPT_DIR"
}

# Function to setup configuration files
setup_configuration() {
    print_status "Setting up configuration files..."
    
    # Create default server config if it doesn't exist
    if [ ! -f "$SERVER_DIR/config/settings.yaml" ]; then
        cat > "$SERVER_DIR/config/settings.yaml" << EOF
# MicroC2 Server Configuration
server:
  host: "localhost"
  port: 8080
  protocol: "https"  # http or https
  
tls:
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
  
directories:
  static: "static"
  uploads: "uploads"
  file_drop: "static/file_drop"
  
logging:
  level: "info"
  file: "server.log"
EOF
        print_success "Default server configuration created"
    else
        print_success "Server configuration already exists"
    fi
}

# Function to run tests
run_tests() {
    if [ "$1" == "--skip-tests" ]; then
        print_warning "Skipping tests as requested"
        return
    fi
    
    print_status "Running tests..."
    
    # Test server build
    cd "$SERVER_DIR"
    if go test ./... >/dev/null 2>&1; then
        print_success "Server tests passed"
    else
        print_warning "Server tests failed or not implemented"
    fi
    
    # Test agent build
    cd "$AGENT_DIR"
    if cargo test >/dev/null 2>&1; then
        print_success "Agent tests passed"
    else
        print_warning "Agent tests failed or not implemented"
    fi
    
    cd "$SCRIPT_DIR"
}

# Function to display final instructions
show_final_instructions() {
    echo
    print_success "Installation completed successfully!"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Start the server:"
    echo "   cd server && ./server"
    echo
    echo "2. Access the web interface:"
    echo "   https://localhost:8080/home/"
    echo
    echo "3. Build additional agent variants:"
    echo "   cd agent"
    echo "   # For Windows 64-bit:"
    echo "   cargo build --release --target x86_64-pc-windows-gnu"
    echo "   # For Windows 32-bit:"
    echo "   cargo build --release --target i686-pc-windows-gnu"
    echo "   # For Linux ARM64:"
    echo "   cargo build --release --target aarch64-unknown-linux-gnu"
    echo
    echo "4. Configuration files:"
    echo "   - Server: server/config/settings.yaml"
    echo "   - Agent: Use web UI payload generator or environment variables"
    echo
    echo "5. File operations:"
    echo "   - Upload/Download: server/uploads/"
    echo "   - File Drop: server/static/file_drop/"
    echo
    print_warning "Remember: This is for academic/research purposes only!"
}

# Function to check for updates
check_for_updates() {
    print_status "Checking for updates..."
    
    if [ ! -d ".git" ]; then
        print_warning "Not a git repository - cannot check for updates"
        return 1
    fi
    
    # Fetch latest changes
    git fetch origin 2>/dev/null
    
    local current_commit=$(git rev-parse HEAD)
    local remote_commit=$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)
    
    if [ "$current_commit" != "$remote_commit" ]; then
        print_warning "Updates available!"
        print_status "Current: ${current_commit:0:8}"
        print_status "Latest:  ${remote_commit:0:8}"
        return 0
    else
        print_success "Already up to date"
        return 1
    fi
}

# Function to backup current installation
backup_installation() {
    print_status "Creating backup of current installation..."
    
    local backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup server binary
    if [ -f "$SERVER_DIR/server" ]; then
        cp "$SERVER_DIR/server" "$backup_dir/server_backup"
        print_success "Server binary backed up"
    fi
    
    # Backup agent binary
    if [ -f "$AGENT_DIR/target/release/agent" ]; then
        mkdir -p "$backup_dir/agent"
        cp "$AGENT_DIR/target/release/agent" "$backup_dir/agent/agent_backup"
        print_success "Agent binary backed up"
    fi
    
    # Backup configuration
    if [ -f "$SERVER_DIR/config/settings.yaml" ]; then
        mkdir -p "$backup_dir/config"
        cp "$SERVER_DIR/config/settings.yaml" "$backup_dir/config/settings.yaml.backup"
        print_success "Configuration backed up"
    fi
    
    # Backup certificates
    if [ -d "$SERVER_DIR/certs" ]; then
        cp -r "$SERVER_DIR/certs" "$backup_dir/certs_backup"
        print_success "Certificates backed up"
    fi
    
    print_success "Backup created in: $backup_dir"
    echo "$backup_dir" > .last_backup
}

# Function to perform git update
update_from_git() {
    print_status "Updating from git repository..."
    
    if [ ! -d ".git" ]; then
        print_error "Not a git repository - cannot update"
        return 1
    fi
    
    # Stash any local changes
    if ! git diff-index --quiet HEAD --; then
        print_status "Stashing local changes..."
        git stash push -m "Auto-stash before update $(date)"
    fi
    
    # Pull latest changes
    if git pull origin main 2>/dev/null || git pull origin master 2>/dev/null; then
        print_success "Successfully updated from git"
        return 0
    else
        print_error "Failed to update from git"
        return 1
    fi
}

# Function to rebuild components
rebuild_components() {
    local force_rebuild="$1"
    
    print_status "Rebuilding components..."
    
    # Check if rebuild is needed
    local needs_server_rebuild=false
    local needs_agent_rebuild=false
    
    if [ "$force_rebuild" == "true" ]; then
        needs_server_rebuild=true
        needs_agent_rebuild=true
        print_status "Force rebuild requested"
    else
        # Check if source files are newer than binaries
        if [ -f "$SERVER_DIR/server" ]; then
            if find "$SERVER_DIR" -name "*.go" -newer "$SERVER_DIR/server" | grep -q .; then
                needs_server_rebuild=true
                print_status "Server source files newer than binary"
            fi
        else
            needs_server_rebuild=true
        fi
        
        if [ -f "$AGENT_DIR/target/release/agent" ]; then
            if find "$AGENT_DIR/src" -name "*.rs" -newer "$AGENT_DIR/target/release/agent" | grep -q .; then
                needs_agent_rebuild=true
                print_status "Agent source files newer than binary"
            fi
        else
            needs_agent_rebuild=true
        fi
    fi
    
    # Rebuild server if needed
    if [ "$needs_server_rebuild" == "true" ] && [ "$AGENT_ONLY" != "true" ]; then
        build_server
    else
        print_success "Server binary is up to date"
    fi
    
    # Rebuild agent if needed
    if [ "$needs_agent_rebuild" == "true" ] && [ "$SERVER_ONLY" != "true" ]; then
        build_agent
    else
        print_success "Agent binary is up to date"
    fi
}

# Function to update dependencies
update_dependencies() {
    print_status "Updating dependencies..."
    
    # Update Go dependencies
    if [ -f "$SERVER_DIR/go.mod" ] && [ "$AGENT_ONLY" != "true" ]; then
        cd "$SERVER_DIR"
        go get -u ./...
        go mod tidy
        print_success "Go dependencies updated"
        cd "$SCRIPT_DIR"
    fi
    
    # Update Rust dependencies
    if [ -f "$AGENT_DIR/Cargo.toml" ] && [ "$SERVER_ONLY" != "true" ]; then
        cd "$AGENT_DIR"
        cargo update
        print_success "Rust dependencies updated"
        cd "$SCRIPT_DIR"
    fi
}

# Function to check build times and suggest updates
check_build_freshness() {
    print_status "Checking build freshness..."
    
    local server_age=""
    local agent_age=""
    local now=$(date +%s)
    
    # Check server binary age
    if [ -f "$SERVER_DIR/server" ]; then
        local server_time=$(stat -c %Y "$SERVER_DIR/server" 2>/dev/null || stat -f %m "$SERVER_DIR/server" 2>/dev/null)
        if [ -n "$server_time" ]; then
            local server_days=$(( (now - server_time) / 86400 ))
            if [ $server_days -gt 7 ]; then
                print_warning "Server binary is $server_days days old"
            else
                print_success "Server binary is recent ($server_days days old)"
            fi
        fi
    fi
    
    # Check agent binary age
    if [ -f "$AGENT_DIR/target/release/agent" ]; then
        local agent_time=$(stat -c %Y "$AGENT_DIR/target/release/agent" 2>/dev/null || stat -f %m "$AGENT_DIR/target/release/agent" 2>/dev/null)
        if [ -n "$agent_time" ]; then
            local agent_days=$(( (now - agent_time) / 86400 ))
            if [ $agent_days -gt 7 ]; then
                print_warning "Agent binary is $agent_days days old"
            else
                print_success "Agent binary is recent ($agent_days days old)"
            fi
        fi
    fi
}

# Add a quick setup function
quick_setup() {
    print_status "Running quick setup for common issues..."
    
    # Fix Rust default toolchain if needed
    if command_exists rustup; then
        if ! rustup default 2>/dev/null | grep -q "default"; then
            print_status "Setting up Rust default toolchain..."
            rustup default stable
            print_success "Rust default toolchain set to stable"
        fi
    fi
}

# Function to show interactive menu
show_interactive_menu() {
    echo
    print_status "=== MicroC2 Installation Menu ==="
    echo
    echo "Please select an option:"
    echo
    echo "0) Install All (Full Installation)"
    echo "1) Check Installation Status"
    echo "2) Update from Git & Rebuild"
    echo "3) Force Rebuild Components"
    echo "4) Install Server Only"
    echo "5) Install Agent Only"
    echo "6) Quick Setup (Fix Common Issues)"
    echo
    echo -n "Enter your choice [0-6]: "
}

# Function to handle interactive mode
handle_interactive_choice() {
    local choice="$1"
    
    case $choice in
        0)
            print_status "Selected: Full Installation"
            return 0  # Continue with normal installation
            ;;
        1)
            print_status "Selected: Check Installation Status"
            check_prerequisites
            check_existing_builds
            check_directories
            check_configuration
            check_certificates
            check_rust_targets
            check_build_freshness
            show_installation_summary
            exit 0
            ;;
        2)
            print_status "Selected: Update from Git & Rebuild"
            UPDATE_MODE=true
            if check_for_updates; then
                update_from_git
                update_dependencies
                rebuild_components "false"
            else
                print_status "No updates available, checking if rebuild needed..."
                rebuild_components "false"
            fi
            show_installation_summary
            exit 0
            ;;
        3)
            print_status "Selected: Force Rebuild Components"
            FORCE_REBUILD=true
            rebuild_components "true"
            show_installation_summary
            exit 0
            ;;
        4)
            print_status "Selected: Install Server Only"
            SERVER_ONLY=true
            return 0  # Continue with server-only installation
            ;;
        5)
            print_status "Selected: Install Agent Only"
            AGENT_ONLY=true
            return 0  # Continue with agent-only installation
            ;;
        6)
            print_status "Selected: Quick Setup"
            quick_setup
            exit 0
            ;;
        *)
            print_error "Invalid choice: $choice"
            print_status "Please enter a number between 0 and 6"
            return 1
            ;;
    esac
}

# Function to get user input with validation
get_user_choice() {
    local choice
    local valid_choice=false
    
    while [ "$valid_choice" = false ]; do
        show_interactive_menu
        read -r choice
        
        # Validate input
        if [[ "$choice" =~ ^[0-6]$ ]]; then
            if handle_interactive_choice "$choice"; then
                valid_choice=true
            fi
        else
            echo
            print_error "Invalid input. Please enter a number between 0 and 6."
            echo
        fi
    done
}

# Main installation function
main() {
    print_banner
    
    # Parse command line arguments
    SKIP_MINGW=false
    SKIP_TESTS=false
    SERVER_ONLY=false
    AGENT_ONLY=false
    UPDATE_MODE=false
    FORCE_REBUILD=false
    UPDATE_DEPS_ONLY=false
    CREATE_BACKUP=false
    INTERACTIVE_MODE=false
    
    # If no arguments provided, use interactive mode
    if [ $# -eq 0 ]; then
        INTERACTIVE_MODE=true
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-mingw)
                SKIP_MINGW=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --server-only)
                SERVER_ONLY=true
                shift
                ;;
            --agent-only)
                AGENT_ONLY=true
                shift
                ;;
            --update)
                UPDATE_MODE=true
                shift
                ;;
            --force-rebuild)
                FORCE_REBUILD=true
                shift
                ;;
            --update-deps)
                UPDATE_DEPS_ONLY=true
                shift
                ;;
            --backup)
                CREATE_BACKUP=true
                shift
                ;;
            --interactive)
                INTERACTIVE_MODE=true
                shift
                ;;
            --check|--verify)
                check_prerequisites
                check_existing_builds
                check_directories
                check_configuration
                check_certificates
                check_rust_targets
                check_build_freshness
                show_installation_summary
                exit 0
                ;;
            --check-updates)
                check_for_updates
                exit $?
                ;;
            --quick-setup)
                quick_setup
                exit 0
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Handle interactive mode
    if [ "$INTERACTIVE_MODE" == "true" ]; then
        get_user_choice
    fi
    
    # Handle update mode
    if [ "$UPDATE_MODE" == "true" ] || [ "$FORCE_REBUILD" == "true" ] || [ "$UPDATE_DEPS_ONLY" == "true" ]; then
        if [ "$CREATE_BACKUP" == "true" ]; then
            backup_installation
        fi
        
        if [ "$UPDATE_MODE" == "true" ]; then
            if check_for_updates; then
                update_from_git
                update_dependencies
                rebuild_components "$FORCE_REBUILD"
            else
                print_status "No updates available, checking if rebuild needed..."
                rebuild_components "$FORCE_REBUILD"
            fi
        elif [ "$UPDATE_DEPS_ONLY" == "true" ]; then
            update_dependencies
        elif [ "$FORCE_REBUILD" == "true" ]; then
            rebuild_components "true"
        fi
        
        show_installation_summary
        exit 0
    fi
    
    # Run verification checks first
    check_prerequisites
    check_existing_builds
    check_directories
    check_configuration
    check_certificates
    check_rust_targets
    
    echo
    print_status "Starting installation process..."
    
    # Run installation steps
    check_prerequisites
    
    if [ "$SKIP_MINGW" == false ] && [ "$AGENT_ONLY" == false ]; then
        install_mingw
    fi
    
    if [ "$AGENT_ONLY" == false ]; then
        setup_rust_targets
    fi
    
    create_directories
    setup_configuration
    generate_certificates
    
    if [ "$AGENT_ONLY" == false ]; then
        build_server
    fi
    
    if [ "$SERVER_ONLY" == false ]; then
        build_agent
    fi
    
    if [ "$SKIP_TESTS" == false ]; then
        run_tests
    fi
    
    show_installation_summary
    show_final_instructions
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Installation Options:"
    echo "  --skip-mingw     Skip MinGW-w64 installation"
    echo "  --skip-tests     Skip running tests"
    echo "  --server-only    Build only the server component"
    echo "  --agent-only     Build only the agent component"
    echo "  --quick-setup    Fix common setup issues"
    echo "  --interactive    Show interactive menu (default if no args)"
    echo
    echo "Update Options:"
    echo "  --update         Update from git and rebuild if needed"
    echo "  --force-rebuild  Force rebuild of all components"
    echo "  --update-deps    Update dependencies only"
    echo "  --backup         Create backup before operations"
    echo
    echo "Information Options:"
    echo "  --check          Verify current installation status"
    echo "  --verify         Same as --check"
    echo "  --check-updates  Check if updates are available"
    echo "  --help           Show this help message"
    echo
    echo "Examples:"
    echo "  $0                    # Show interactive menu"
    echo "  $0 --interactive      # Show interactive menu explicitly"
    echo "  $0 --check           # Check what's already installed"
    echo "  $0 --update          # Update and rebuild if needed"
    echo "  $0 --force-rebuild   # Force rebuild all components"
    echo "  $0 --server-only     # Build only server (non-interactive)"
}

# Run main function with all arguments
main "$@"